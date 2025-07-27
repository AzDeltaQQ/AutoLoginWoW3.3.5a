#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <TlHelp32.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "config.h"

// Client state enumeration based on IsLoading? global variable
enum ClientState {
    DISCONNECTED,       // IsLoading == 0
    LOGGING_IN,         // IsLoading == 1 (Authenticating to BNet)
    SELECTING_REALM,    // IsLoading == 4 (Realm List is up)
    CONNECTING_TO_REALM,// IsLoading == 2 (In transition to game server)
    AUTHENTICATED       // auth_flag == 1 (At character select)
};

class Logger {
private:
    std::ofstream logFile;
    std::string logFileName;
    
public:
    Logger() {
        // Create log file with timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << "WoWAutoLogin_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".log";
        logFileName = ss.str();
        
        logFile.open(logFileName, std::ios::out | std::ios::app);
        if (logFile.is_open()) {
            logFile << "=== WoW Auto-Login Log Started ===" << std::endl;
            logFile.flush();
        }
    }
    
    ~Logger() {
        if (logFile.is_open()) {
            logFile << "=== WoW Auto-Login Log Ended ===" << std::endl;
            logFile.close();
        }
    }
    
    void Log(const std::string& message, const std::string& level = "INFO") {
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            
            logFile << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
                   << "." << std::setfill('0') << std::setw(3) << ms.count() << "] "
                   << "[" << level << "] " << message << std::endl;
            logFile.flush();
        }
        
        // Also output to console
        std::cout << "[" << level << "] " << message << std::endl;
    }
    
    std::string GetLogFileName() const {
        return logFileName;
    }
};

class WoWAutoLogin {
private:
    HANDLE processHandle;
    DWORD processId;
    std::string accountName;
    std::string password;
    bool isRunning;
    Logger logger;

public:
    static WoWAutoLogin* instance;

public:
    WoWAutoLogin(const std::string& account, const std::string& pass)
        : accountName(account), password(pass), isRunning(false) {
        processHandle = NULL;
        processId = 0;
    }

    ~WoWAutoLogin() {
        if (processHandle) CloseHandle(processHandle);
        if (instance == this) instance = nullptr;
    }

    void Log(const std::string& message, bool verbose = false) {
        if (!verbose || (DEBUG_OUTPUT && VERBOSE_LOGGING)) {
            logger.Log(message, verbose ? "VERBOSE" : "INFO");
        }
    }

    bool AttachToProcess() {
        Log("Attempting to attach to WoW process...");
        processId = FindWoWProcess();
        if (processId == 0) {
            Log("WoW process not found!", false);
            return false;
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            Log("Failed to open WoW process! IMPORTANT: Please run this program as an Administrator. Error: " + std::to_string(GetLastError()), false);
            return false;
        }
        Log("Successfully attached to WoW process (PID: " + std::to_string(processId) + ")", false);
        return true;
    }

    template<typename T>
    T ReadMemory(DWORD address) {
        T value{}; // Initialize to zero
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), NULL)) {
            std::stringstream ss;
            ss << "ReadProcessMemory FAILED at address 0x" << std::hex << address << ". Error: " << GetLastError();
            Log(ss.str(), true);
        }
        return value;
    }

    bool WriteString(DWORD address, const std::string& str) {
        return WriteProcessMemory(processHandle, (LPVOID)address, str.c_str(), str.length() + 1, NULL);
    }

    DWORD AllocateRemoteMemory(size_t size) {
        // THIS IS THE FIX. Change the memory protection flag.
        DWORD allocatedAddr = (DWORD)VirtualAllocEx(
            processHandle,
            NULL,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE // <-- CORRECTED FLAG
        );
        
        if (VERBOSE_LOGGING) {
            if (allocatedAddr) {
                std::stringstream ss;
                ss << "Allocated " << size << " bytes of EXECUTABLE memory at 0x" << std::hex << allocatedAddr;
                Log(ss.str(), true);
            } else {
                Log("Failed to allocate remote memory. Error: " + std::to_string(GetLastError()), true);
            }
        }
        return allocatedAddr;
    }

    bool FreeRemoteMemory(DWORD address) {
        return VirtualFreeEx(processHandle, (LPVOID)address, 0, MEM_RELEASE);
    }

    // Generic __cdecl remote call
    bool CallCdeclFunction(DWORD functionAddr, const std::vector<DWORD>& args) {
        std::vector<BYTE> stub;
        // push arguments
        for (auto it = args.rbegin(); it != args.rend(); ++it) {
            stub.push_back(0x68); // PUSH
            DWORD arg = *it;
            stub.insert(stub.end(), (BYTE*)&arg, (BYTE*)&arg + 4);
        }
        // mov eax, functionAddr
        stub.push_back(0xB8);
        stub.insert(stub.end(), (BYTE*)&functionAddr, (BYTE*)&functionAddr + 4);
        // call eax
        stub.push_back(0xFF);
        stub.push_back(0xD0);
        // add esp, X (cdecl cleanup)
        if (!args.empty()) {
            stub.push_back(0x83); stub.push_back(0xC4); stub.push_back(args.size() * sizeof(DWORD));
        }
        // ret
        stub.push_back(0xC3);
        
        DWORD stubAddr = AllocateRemoteMemory(stub.size());
        if (!stubAddr) return false;
        
        WriteProcessMemory(processHandle, (LPVOID)stubAddr, stub.data(), stub.size(), NULL);
        HANDLE thread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)stubAddr, NULL, 0, NULL);
        
        bool success = (thread != NULL);
        if (thread) {
            WaitForSingleObject(thread, FUNCTION_CALL_TIMEOUT * 1000);
            CloseHandle(thread);
        }
        
        FreeRemoteMemory(stubAddr);
        return success;
    }

    // Generic __thiscall remote call
    bool CallThiscallFunction(DWORD functionAddr, DWORD thisPtr, const std::vector<DWORD>& args) {
        std::vector<BYTE> stub;
        // mov ecx, thisPtr
        stub.push_back(0xB9);
        stub.insert(stub.end(), (BYTE*)&thisPtr, (BYTE*)&thisPtr + 4);
        // push arguments
        for (auto it = args.rbegin(); it != args.rend(); ++it) {
            stub.push_back(0x68); // PUSH
            DWORD arg = *it;
            stub.insert(stub.end(), (BYTE*)&arg, (BYTE*)&arg + 4);
        }
        // mov eax, functionAddr
        stub.push_back(0xB8);
        stub.insert(stub.end(), (BYTE*)&functionAddr, (BYTE*)&functionAddr + 4);
        // call eax
        stub.push_back(0xFF);
        stub.push_back(0xD0);
        // ret (callee cleanup for __thiscall)
        stub.push_back(0xC3);
        
        DWORD stubAddr = AllocateRemoteMemory(stub.size());
        if (!stubAddr) return false;
        
        WriteProcessMemory(processHandle, (LPVOID)stubAddr, stub.data(), stub.size(), NULL);
        HANDLE thread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)stubAddr, NULL, 0, NULL);
        
        bool success = (thread != NULL);
        if (thread) {
            WaitForSingleObject(thread, FUNCTION_CALL_TIMEOUT * 1000);
            CloseHandle(thread);
        }
        
        FreeRemoteMemory(stubAddr);
        return success;
    }

    bool InitiateLogin() {
        Log("Setting last realm CVar and calling processServerLogin...", false);
        
        // --- STEP 1: Set the 'realmName' CVar. This is a critical prerequisite. ---
        DWORD remoteRealmName = AllocateRemoteMemory(accountName.length() + 1); // Use accountName buffer temporarily
        if (!remoteRealmName) return false;
        // The actual realm list isn't available, but the CVar is often used for the login packet header.
        // We'll use a placeholder or the target realm name. For now, we use a placeholder.
        WriteString(remoteRealmName, "Kezan"); // Must match a real realm on the server
        
        // Call resume_last_realm(char* realm)
        CallCdeclFunction(RESUME_LAST_REALM_FUNC, { remoteRealmName });
        FreeRemoteMemory(remoteRealmName);

        // --- STEP 2: Call the main login function as before. ---
        DWORD remoteAccount = AllocateRemoteMemory(accountName.length() + 1);
        DWORD remotePassword = AllocateRemoteMemory(password.length() + 1);
        if (!remoteAccount || !remotePassword) return false;

        WriteString(remoteAccount, accountName);
        WriteString(remotePassword, password);
        
        bool success = CallCdeclFunction(PROCESS_SERVER_LOGIN_FUNC, { remoteAccount, remotePassword });
        
        FreeRemoteMemory(remoteAccount);
        FreeRemoteMemory(remotePassword);
        return success;
    }

    // THIS IS THE DEFINITIVE REALM SELECTION FUNCTION
    bool SelectRealm(const std::string& realmName) {
        DWORD pNetClient = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
        if (!pNetClient) return false;
        
        int realmCount = ReadMemory<int>(pNetClient + REALM_COUNT_OFFSET);
        if (realmCount <= 0) return false;

        DWORD realmArray = ReadMemory<DWORD>(pNetClient + REALM_LIST_PTR_OFFSET);
        for (int i = 0; i < realmCount; i++) {
            char currentRealmName[64] = {0};
            DWORD realmEntryAddr = realmArray + (i * REALM_STRUCT_SIZE);
            ReadProcessMemory(processHandle, (LPCVOID)(realmEntryAddr + REALM_NAME_OFFSET), currentRealmName, sizeof(currentRealmName)-1, NULL);

            if (_stricmp(currentRealmName, realmName.c_str()) == 0) {
                Log("Found realm '" + realmName + "'. Selecting via FrameScript_Execute...", false);

                // Lua is 1-based, so we use i + 1. Category is 1.
                std::string luaScript = "select_realm(1, " + std::to_string(i + 1) + ")";

                DWORD remoteScript = AllocateRemoteMemory(luaScript.length() + 1);
                DWORD remoteSourceName = AllocateRemoteMemory(16); // "AutoLogin" or similar
                if (!remoteScript || !remoteSourceName) return false;

                WriteString(remoteScript, luaScript);
                WriteString(remoteSourceName, "AutoLogin");
                
                // FrameScript_Execute is __cdecl(char* code, char* sourceName, int 0)
                bool success = CallCdeclFunction(FRAMESCRIPT_EXECUTE_FUNC, { remoteScript, remoteSourceName, 0 });
                
                FreeRemoteMemory(remoteScript);
                FreeRemoteMemory(remoteSourceName);
                return success;
            }
        }
        Log("Could not find realm: '" + realmName + "'", false);
        return false;
    }

    ClientState GetClientState() {
        // First, check the most definitive state: fully authenticated at char select.
        DWORD pClientConnection = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
        if (pClientConnection && pClientConnection != 0xFFFFFFFF) {
            if (ReadMemory<uint8_t>(pClientConnection + AUTH_STATUS_FLAG_OFFSET) == 1) {
                return AUTHENTICATED;
            }
        }

        // If not, check the global loading screen state variable.
        DWORD loadingState = ReadMemory<DWORD>(IS_LOADING_ADDR);
        switch (loadingState) {
            case 1: return LOGGING_IN;
            case 2: return CONNECTING_TO_REALM;
            case 4: return SELECTING_REALM;
            default: return DISCONNECTED;
        }
    }

    // NEW FUNCTION: Gracefully resets the client UI
    void ResetClientState() {
        Log("Attempting to gracefully reset client state...", false);
        DWORD pNetClient = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
        if (!pNetClient || pNetClient == 0xFFFFFFFF) {
            Log("NetClient object no longer exists, no need to reset state.", true);
            return;
        }
        
        DWORD vtable = ReadMemory<DWORD>(pNetClient);
        if (!vtable) return;
        
        DWORD resetFunc = ReadMemory<DWORD>(vtable + VTABLE_RESET_OFFSET);
        if (!resetFunc) return;
        
        Log("Calling ResetLoginState virtual function.", true);
        CallThiscallFunction(resetFunc, pNetClient, {});
    }

    // NEW FUNCTION TO HANDLE STUCK DIALOGS
    void ClickCancelButton() {
        Log("Sending 'Cancel' event to clear any stuck dialogs...", true);
        CallCdeclFunction(ON_REALMLIST_CANCEL_FUNC, {});
    }

    void Run(const std::string& targetRealm) {
        if (!AttachToProcess()) return;
        isRunning = true;
        Log("Starting main loop. Target realm: '" + targetRealm + "'", false);

        bool hasBeenAuthenticated = false;

        while (isRunning) {
            ClientState currentState = GetClientState();

            switch (currentState) {
                case AUTHENTICATED:
                    Log("Client is authenticated at character select. Monitoring...", true);
                    hasBeenAuthenticated = true;
                    std::this_thread::sleep_for(std::chrono::milliseconds(DISCONNECT_CHECK_INTERVAL));
                    break;

                case LOGGING_IN:
                case CONNECTING_TO_REALM:
                    Log("Client is busy connecting. Waiting...", true);
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    break;

                case SELECTING_REALM:
                    Log("Client is at realm selection. Attempting to select realm...", false);
                    if (!SelectRealm(targetRealm)) {
                        Log("Failed to send realm selection packet. Resetting.", false);
                        ResetClientState();
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                    break;

                case DISCONNECTED:
                    Log("\n--- Client is disconnected. Starting login sequence. ---", false);
                    
                    // If we have been authenticated before, it means we disconnected.
                    // If a dialog box is stuck, this will clear it.
                    if (hasBeenAuthenticated) {
                        ClickCancelButton();
                        ResetClientState();
                        std::this_thread::sleep_for(std::chrono::seconds(1)); // Give UI time to react
                    }

                    InitiateLogin();
                    std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                    break;
            }
        }
        Log("Auto-login loop stopped.", false);
    }

    void Stop() { isRunning = false; }
    
    std::string GetLogFileName() const {
        return logger.GetLogFileName();
    }

private:
    DWORD FindWoWProcess() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            Log("CreateToolhelp32Snapshot failed. Error: " + std::to_string(GetLastError()), false);
            return 0;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, PROCESS_NAME) == 0) {
                    CloseHandle(snapshot);
                    Log("Found WoW process: " + std::string(pe32.szExeFile) + " (PID: " + std::to_string(pe32.th32ProcessID) + ")", true);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        Log("WoW process with name '" + std::string(PROCESS_NAME) + "' not found.");
        return 0;
    }
};

// Initialize the static instance pointer
WoWAutoLogin* WoWAutoLogin::instance = nullptr;

// Ctrl+C handler function
BOOL WINAPI CtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT) {
        std::cout << "\nStopping auto-login..." << std::endl;
        if (WoWAutoLogin::instance) {
            WoWAutoLogin::instance->Stop();
        }
        return TRUE;
    }
    return FALSE;
}

int main() {
    // Set console window title to hide computer name
    SetConsoleTitleA("WoW Auto-Login");
    
    std::cout << "WoW Auto-Login Program" << std::endl;
    std::cout << "======================" << std::endl;
    
    std::string account, password, realm;
    
    std::cout << "Enter your account name/email: ";
    std::getline(std::cin, account);
    
    std::cout << "Enter your password: ";
    std::getline(std::cin, password);
    
    std::cout << "Enter target realm name: ";
    std::getline(std::cin, realm);
    
    if (account.empty() || password.empty() || realm.empty()) {
        std::cout << "Invalid credentials! Account, password, and realm cannot be empty." << std::endl;
        return 1;
    }
    
    // Set up Ctrl+C handler
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    
    try {
        WoWAutoLogin autoLogin(account, password);
        WoWAutoLogin::instance = &autoLogin;
        std::cout << "Log file: " << autoLogin.GetLogFileName() << std::endl;
        autoLogin.Run(realm);
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    return 0;
} 