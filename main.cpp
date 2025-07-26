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

    bool InitiateLogin() {
        Log("Calling processServerLogin function at 0x4D8A30...", false);
        
        DWORD remoteAccount = AllocateRemoteMemory(accountName.length() + 1);
        DWORD remotePassword = AllocateRemoteMemory(password.length() + 1);
        if (!remoteAccount || !remotePassword) { 
            Log("Failed to allocate memory for credentials.", false);
            return false; 
        }

        WriteString(remoteAccount, accountName);
        WriteString(remotePassword, password);

        // This function is __cdecl(char* account, char* password)
        std::vector<BYTE> stub;
        DWORD funcAddr = PROCESS_SERVER_LOGIN_FUNC;

        // push password_ptr
        stub.push_back(0x68);
        stub.insert(stub.end(), (BYTE*)&remotePassword, (BYTE*)&remotePassword + 4);
        // push account_ptr
        stub.push_back(0x68);
        stub.insert(stub.end(), (BYTE*)&remoteAccount, (BYTE*)&remoteAccount + 4);
        // mov eax, functionAddr
        stub.push_back(0xB8);
        stub.insert(stub.end(), (BYTE*)&funcAddr, (BYTE*)&funcAddr + 4);
        // call eax
        stub.push_back(0xFF);
        stub.push_back(0xD0);
        // add esp, 8 (cdecl cleanup)
        stub.push_back(0x83); stub.push_back(0xC4); stub.push_back(0x08);
        // ret
        stub.push_back(0xC3);

        DWORD stubAddr = AllocateRemoteMemory(stub.size());
        if (!stubAddr) { 
            FreeRemoteMemory(remoteAccount);
            FreeRemoteMemory(remotePassword);
            return false; 
        }
        
        WriteProcessMemory(processHandle, (LPVOID)stubAddr, stub.data(), stub.size(), NULL);
        HANDLE thread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)stubAddr, NULL, 0, NULL);
        
        bool success = (thread != NULL);
        if (thread) {
            WaitForSingleObject(thread, FUNCTION_CALL_TIMEOUT * 1000);
            CloseHandle(thread);
        }
        
        FreeRemoteMemory(stubAddr);
        FreeRemoteMemory(remoteAccount);
        FreeRemoteMemory(remotePassword);
        
        return success;
    }

    bool SelectRealm(const std::string& realmName) {
        Log("Waiting for NetClient pointer to be created by login process...", false);
        DWORD pNetClient = 0;
        for (int i = 0; i < 15; i++) {
            pNetClient = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
            if (pNetClient && pNetClient != 0xFFFFFFFF) break;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!pNetClient) {
             Log("NetClient pointer was not created. Login may have failed.", false);
             return false;
        }

        Log("Waiting for realm list...", false);
        for (int i = 0; i < REALM_LIST_TIMEOUT; i++) {
            if (ReadMemory<int>(pNetClient + REALM_COUNT_OFFSET) > 0) break;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        int realmCount = ReadMemory<int>(pNetClient + REALM_COUNT_OFFSET);
        if (realmCount <= 0) {
            Log("Timeout or error waiting for realm list.", false);
            return false;
        }
        
        DWORD realmArray = ReadMemory<DWORD>(pNetClient + REALM_LIST_PTR_OFFSET);
        for (int i = 0; i < realmCount; i++) {
            char currentRealmName[64] = {0};
            ReadProcessMemory(processHandle, (LPCVOID)(realmArray + (i * REALM_STRUCT_SIZE) + REALM_NAME_OFFSET), currentRealmName, sizeof(currentRealmName)-1, NULL);

            if (_stricmp(currentRealmName, realmName.c_str()) == 0) {
                Log("Found realm '" + realmName + "'. Connecting...", false);
                // processBNetAuthPacket is __thiscall
                std::vector<BYTE> stub;
                DWORD funcAddr = PROCESS_BNET_AUTH_PACKET;
                DWORD realmIndex = i;

                stub.push_back(0xB9); // mov ecx, pNetClient
                stub.insert(stub.end(), (BYTE*)&pNetClient, (BYTE*)&pNetClient + 4);
                stub.push_back(0x68); // push realmIndex
                stub.insert(stub.end(), (BYTE*)&realmIndex, (BYTE*)&realmIndex + 4);
                stub.push_back(0xB8); // mov eax, funcAddr
                stub.insert(stub.end(), (BYTE*)&funcAddr, (BYTE*)&funcAddr + 4);
                stub.push_back(0xFF); // call eax
                stub.push_back(0xD0);
                stub.push_back(0xC3); // ret (this func is __thiscall, callee cleanup)

                DWORD stubAddr = AllocateRemoteMemory(stub.size());
                if (!stubAddr) return false;
                WriteProcessMemory(processHandle, (LPVOID)stubAddr, stub.data(), stub.size(), NULL);
                HANDLE thread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)stubAddr, NULL, 0, NULL);
                WaitForSingleObject(thread, FUNCTION_CALL_TIMEOUT * 1000);
                CloseHandle(thread);
                FreeRemoteMemory(stubAddr);
                return true;
            }
        }
        Log("Could not find realm: '" + realmName + "'", false);
        return false;
    }

    bool CheckIsAuthenticated() {
        DWORD pClientConnection = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
        if (!pClientConnection || pClientConnection == 0xFFFFFFFF) return false;
        return ReadMemory<uint8_t>(pClientConnection + AUTH_STATUS_FLAG_OFFSET) == 1;
    }

    void Run(const std::string& targetRealm) {
        if (!AttachToProcess()) return;
        isRunning = true;
        Log("Starting main loop. Target realm: '" + targetRealm + "'", false);

        while (isRunning) {
            if (!CheckIsAuthenticated()) {
                Log("\n--- Client not authenticated. Starting login sequence. ---", false);
                
                if (InitiateLogin()) {
                    Log("Login request sent. Waiting for realm list...", false);
                    if (SelectRealm(targetRealm)) {
                        Log("Successfully connected to realm!", false);
                    } else {
                        Log("Failed to select realm after login attempt.", false);
                    }
                }
                std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
            } else {
                Log("Client is authenticated. Monitoring...", true);
                std::this_thread::sleep_for(std::chrono::milliseconds(DISCONNECT_CHECK_INTERVAL));
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