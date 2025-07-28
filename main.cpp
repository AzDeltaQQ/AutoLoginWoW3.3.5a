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
#include <time.h>
#include "config.h"

// Enhanced client state enumeration with more detailed states
enum ClientState {
    AT_LOGIN_SCREEN,      // Glue screen, no operations active.
    CONNECTING_TO_AUTH,   // "Connecting" dialog is visible.
    AUTH_SUCCESS,         // Successfully authenticated, downloading realm list.
    REALM_LIST,           // Realm list is visible.
    CONNECTING_TO_REALM,  // "Logging in to game server..."
    CHARACTER_SELECT,     // Success! At character select screen.
    ERROR_STATE           // An error dialog is visible.
};

// ClientOperation enum is now defined in config.h

// ConnectionStatus enum is now defined in config.h

// Helper to make logs more readable
std::string StateToString(ClientState state) {
    switch (state) {
        case AT_LOGIN_SCREEN: return "AT_LOGIN_SCREEN";
        case CONNECTING_TO_AUTH: return "CONNECTING_TO_AUTH";
        case AUTH_SUCCESS: return "AUTH_SUCCESS";
        case REALM_LIST: return "REALM_LIST";
        case CONNECTING_TO_REALM: return "CONNECTING_TO_REALM";
        case CHARACTER_SELECT: return "CHARACTER_SELECT";
        case ERROR_STATE: return "ERROR_STATE";
        default: return "UNKNOWN";
    }
}

class Logger {
private:
    std::ofstream logFile;
    std::string logFileName;
    
public:
    Logger() {
        // Create log file with timestamp
        auto now = std::chrono::system_clock::now();
        time_t time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now;
        localtime_s(&tm_now, &time_t_now);
        std::stringstream ss;
        ss << "WoWAutoLogin_" << std::put_time(&tm_now, "%Y%m%d_%H%M%S") << ".log";
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
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::tm tm_now;
            localtime_s(&tm_now, &time_t_now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            
            logFile << "[" << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S") 
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
    bool m_loginAttempted; // The crucial internal state flag
    Logger logger;
    ClientState lastState;

public:
    static WoWAutoLogin* instance;

    WoWAutoLogin(const std::string& account, const std::string& pass)
        : accountName(account), password(pass), isRunning(false), m_loginAttempted(false), lastState((ClientState)-1) {
        processHandle = NULL;
        processId = 0;
    }

    ~WoWAutoLogin() {
        if (processHandle) CloseHandle(processHandle);
        if (instance == this) instance = nullptr;
    }

    void Log(const std::string& message, const std::string& level = "INFO", bool verbose = false) {
        if (!verbose || (DEBUG_OUTPUT && VERBOSE_LOGGING)) {
            logger.Log(message, level);
        }
    }

    bool AttachToProcess() {
        Log("Attempting to attach to WoW process...", "INFO");
        processId = FindWoWProcess();
        if (processId == 0) {
            Log("WoW process not found!", "ERROR");
            return false;
        }

        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!processHandle) {
            Log("Failed to open WoW process! IMPORTANT: Please run this program as an Administrator. Error: " + std::to_string(GetLastError()), "ERROR");
            return false;
        }
        Log("Successfully attached to WoW process (PID: " + std::to_string(processId) + ")", "INFO");
        return true;
    }

    template<typename T>
    T ReadMemory(DWORD address) {
        T value{}; // Initialize to zero
        if (!ReadProcessMemory(processHandle, (LPCVOID)address, &value, sizeof(T), NULL)) {
            std::stringstream ss;
            ss << "ReadProcessMemory FAILED at address 0x" << std::hex << address << ". Error: " << GetLastError();
            Log(ss.str(), "VERBOSE", true);
        }
        return value;
    }

    bool WriteString(DWORD address, const std::string& str) {
        return WriteProcessMemory(processHandle, (LPVOID)address, str.c_str(), str.length() + 1, NULL);
    }

    DWORD AllocateRemoteMemory(size_t size) {
        DWORD allocatedAddr = (DWORD)VirtualAllocEx(
            processHandle,
            NULL,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (VERBOSE_LOGGING) {
            if (allocatedAddr) {
                std::stringstream ss;
                ss << "Allocated " << size << " bytes of EXECUTABLE memory at 0x" << std::hex << allocatedAddr;
                Log(ss.str(), "VERBOSE", true);
            } else {
                Log("Failed to allocate remote memory. Error: " + std::to_string(GetLastError()), "VERBOSE", true);
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
        Log("Calling processServerLogin function...", "ACTION");
        DWORD remoteAccount = AllocateRemoteMemory(accountName.length() + 1);
        DWORD remotePassword = AllocateRemoteMemory(password.length() + 1);
        if (!remoteAccount || !remotePassword) { return false; }

        WriteString(remoteAccount, accountName);
        WriteString(remotePassword, password);
        
        bool success = CallCdeclFunction(PROCESS_SERVER_LOGIN_FUNC, { remoteAccount, remotePassword });
        
        FreeRemoteMemory(remoteAccount);
        FreeRemoteMemory(remotePassword);
        return success;
    }

    bool SelectRealm(const std::string& realmName) {
        DWORD pNetClient = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
        if (!pNetClient) return false;
        
        int realmCount = ReadMemory<int>(pNetClient + REALM_COUNT_OFFSET);
        if (realmCount <= 0) {
             Log("Realm count is zero or invalid.", "WARN");
             return false;
        }

        DWORD realmArray = ReadMemory<DWORD>(pNetClient + REALM_LIST_PTR_OFFSET);
        for (int i = 0; i < realmCount; i++) {
            char currentRealmName[64] = {0};
            DWORD realmEntryAddr = realmArray + (i * REALM_STRUCT_SIZE);
            ReadProcessMemory(processHandle, (LPCVOID)(realmEntryAddr + REALM_NAME_OFFSET), currentRealmName, sizeof(currentRealmName)-1, NULL);

            if (_stricmp(currentRealmName, realmName.c_str()) == 0) {
                Log("Found realm '" + realmName + "'. Selecting via FrameScript_Execute...", "ACTION");
                std::string luaScript = "SelectRealm(" + std::to_string(i + 1) + ")";
                
                DWORD remoteScript = AllocateRemoteMemory(luaScript.length() + 1);
                DWORD remoteSourceName = AllocateRemoteMemory(16);
                if (!remoteScript || !remoteSourceName) return false;

                WriteString(remoteScript, luaScript);
                WriteString(remoteSourceName, "AutoLogin");
                bool success = CallCdeclFunction(FRAMESCRIPT_EXECUTE_FUNC, { remoteScript, remoteSourceName, 0 });
                
                FreeRemoteMemory(remoteScript);
                FreeRemoteMemory(remoteSourceName);
                return success;
            }
        }
        Log("Could not find realm: '" + realmName + "'", "ERROR");
        return false;
    }
    
    // Removed old Lua functions that are no longer needed for state detection
    // std::string ExecuteLuaAndGetString(const std::string& luaExpression) { /* ... */ }
    // bool IsCharacterSelectVisible() { /* ... */ }
    // bool IsGlueDialogVisible() { /* ... */ }

    ConnectionStatus GetGlueErrorStatus() {
        return ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
    }
    
    // THIS IS THE NEW, MORE ACCURATE STATE DETECTION
    ClientState GetClientState() {
        // Priority 1: Read the game's own UI state string.
        std::string stateStr = ReadGlobalString(GAMESTATE_STRING_ADDR);

        if (stateStr == "charselect") {
            return CHARACTER_SELECT;
        }
        
        if (stateStr == "charcreate") {
            // Handle character creation screen if necessary, for now treat as success
            return CHARACTER_SELECT; 
        }

        // Priority 2: Check for an ACTIVE error dialog. An error code is only valid if a dialog is shown.
        if (IsGlueDialogVisible()) {
            return ERROR_STATE;
        }

        // Priority 3: Check the native connection object for intermediate network states.
        DWORD pClientConnection = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
        if (pClientConnection && pClientConnection != 0xFFFFFFFF) {
            ClientOperation op = ReadMemory<ClientOperation>(pClientConnection + CCLIENTCONNECTION_OPERATION_OFFSET);
            ConnectionStatus status = ReadMemory<ConnectionStatus>(pClientConnection + CCLIENTCONNECTION_STATUS_OFFSET);

            switch (op) {
                case COP_CONNECT:
                case COP_HANDSHAKE:
                    return CONNECTING_TO_AUTH;
                case COP_AUTHENTICATE:
                    if (status == AUTH_OK) return AUTH_SUCCESS;
                    return CONNECTING_TO_AUTH;
                case COP_GET_REALMS:
                    if (status == REALM_LIST_SUCCESS) return REALM_LIST;
                    return AUTH_SUCCESS;
                case COP_LOGIN_CHARACTER:
                    return CONNECTING_TO_REALM;
            }
        }

        // Priority 4: If the state string is "login" and no dialogs are visible, we are at the login screen.
        if (stateStr == "login") {
            return AT_LOGIN_SCREEN;
        }
        
        // Fallback: If we're in an unknown state, assume we need to be at the login screen.
        return AT_LOGIN_SCREEN;
    }

    std::string ReadGlobalString(DWORD address, size_t maxSize = 64) {
        std::vector<char> buffer(maxSize);
        if (ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), maxSize, NULL)) {
            // Ensure null termination
            buffer[maxSize - 1] = '\0';
            return std::string(buffer.data());
        }
        return "";
    }

    // Re-added Lua interaction functions
    std::string ExecuteLuaAndGetString(const std::string& luaExpression) {
        std::string tempVarName = "AutoLoginResultVar";
        std::string scriptToRun = tempVarName + " = tostring(" + luaExpression + ")";

        DWORD remoteScript = AllocateRemoteMemory(scriptToRun.length() + 1);
        DWORD remoteSourceName = AllocateRemoteMemory(16);
        if (!remoteScript || !remoteSourceName) {
            if(remoteScript) FreeRemoteMemory(remoteScript);
            if(remoteSourceName) FreeRemoteMemory(remoteSourceName);
            return "";
        }

        WriteString(remoteScript, scriptToRun);
        WriteString(remoteSourceName, "AutoLogin");
        CallCdeclFunction(FRAMESCRIPT_EXECUTE_FUNC, { remoteScript, remoteSourceName, 0 });
        FreeRemoteMemory(remoteScript);
        FreeRemoteMemory(remoteSourceName);

        const size_t bufferSize = 256;
        DWORD remoteResultBuffer = AllocateRemoteMemory(bufferSize);
        DWORD remoteVarName = AllocateRemoteMemory(tempVarName.length() + 1);
        if (!remoteResultBuffer || !remoteVarName) {
            if(remoteResultBuffer) FreeRemoteMemory(remoteResultBuffer);
            if(remoteVarName) FreeRemoteMemory(remoteVarName);
            return "";
        }
        
        WriteString(remoteVarName, tempVarName);
        CallCdeclFunction(FRAMESCRIPT_GETTEXT_FUNC, { remoteVarName, remoteResultBuffer, (DWORD)bufferSize });

        char resultBuffer[bufferSize] = {0};
        ReadProcessMemory(processHandle, (LPCVOID)remoteResultBuffer, resultBuffer, bufferSize - 1, NULL);

        FreeRemoteMemory(remoteVarName);
        FreeRemoteMemory(remoteResultBuffer);
        
        return std::string(resultBuffer);
    }

    bool IsGlueDialogVisible() {
        std::string result = ExecuteLuaAndGetString("GlueDialog and GlueDialog:IsVisible()");
        return result == "true";
    }


    void ResetLoginState() {
        Log("Calling reset function to dismiss dialog and clear state...", "ACTION");
        CallCdeclFunction(RESET_LOGIN_STATE_FUNC, {});
    }

    void Run(const std::string& targetRealm) {
        if (!AttachToProcess()) return;
        isRunning = true;
        Log("Starting main loop. Target realm: '" + targetRealm + "'", "INFO");

        auto actionTimer = std::chrono::steady_clock::now();
        bool realmSelectAttempted = false; // Add this flag

        while (isRunning) {
            ClientState currentState = GetClientState();
            
            if (currentState != lastState) {
                Log("State changed to: " + StateToString(currentState), "STATE");
                lastState = currentState;
                actionTimer = std::chrono::steady_clock::now();
            }

            switch (currentState) {
                case AT_LOGIN_SCREEN:
                    if (!m_loginAttempted) {
                        Log("Client is at login screen. Initiating login.", "INFO");
                        InitiateLogin();
                        m_loginAttempted = true; 
                        realmSelectAttempted = false; // Reset realm selection flag on new login
                    }
                    break;

                case CONNECTING_TO_AUTH:
                case CONNECTING_TO_REALM: {
                    Log("Waiting for connection...", "VERBOSE", true);
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - actionTimer).count();
                    if (elapsed > LOGIN_TIMEOUT) {
                        Log("Connection timed out. Resetting state.", "WARN");
                        ResetLoginState();
                        m_loginAttempted = false; 
                        std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                    }
                    break;
                }

                case ERROR_STATE: {
                    DWORD pClientConnection = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
                    // Prioritize reading the more specific error code from the connection object if it exists
                    ConnectionStatus status = pClientConnection ? 
                                               ReadMemory<ConnectionStatus>(pClientConnection + CCLIENTCONNECTION_STATUS_OFFSET) : 
                                               GetGlueErrorStatus();
                    
                    Log("Detected error state with ConnectionStatus: " + std::to_string(status), "ERROR");
                    
                    switch (status) {
                        case RESPONSE_FAILED_TO_CONNECT:
                        case RESPONSE_DISCONNECTED:
                        case AUTH_LOGIN_SERVER_NOT_FOUND:
                            Log("Error: Server seems to be down. Retrying in " + std::to_string(RECONNECT_DELAY) + "s.", "WARN");
                            ResetLoginState();
                            m_loginAttempted = false;
                            std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                            break;
                        case AUTH_INCORRECT_PASSWORD:
                        case AUTH_UNKNOWN_ACCOUNT:
                        case AUTH_BANNED:
                        case AUTH_SUSPENDED:
                            Log("Error: Unrecoverable account issue (Banned/Bad Pass/etc). Halting.", "FATAL");
                            isRunning = false;
                            break;
                        default:
                            Log("Unhandled error (" + std::to_string(status) + "). Resetting and retrying.", "WARN");
                            ResetLoginState();
                            m_loginAttempted = false;
                            std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                            break;
                    }
                    break;
                }
                
                case AUTH_SUCCESS:
                    Log("Authentication successful. Waiting for realm list...", "INFO");
                    break;

                case REALM_LIST:
                    if (!realmSelectAttempted) { // Use the new flag here
                        m_loginAttempted = false;
                        Log("Realm list is ready. Selecting realm: '" + targetRealm + "'", "INFO");
                        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                        if (!SelectRealm(targetRealm)) {
                            Log("Failed to select realm. Check realm name.", "FATAL");
                            isRunning = false;
                        }
                        realmSelectAttempted = true; // Prevent spamming SelectRealm
                    }
                    break;

                case CHARACTER_SELECT:
                    Log("Successfully logged in to character select. Monitoring.", "SUCCESS");
                    m_loginAttempted = false; 
                    realmSelectAttempted = false;
                    std::this_thread::sleep_for(std::chrono::seconds(15));
                    break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        Log("Auto-login loop stopped.", "INFO");
    }

    void Stop() { isRunning = false; }
    
    std::string GetLogFileName() const {
        return logger.GetLogFileName();
    }

private:
    DWORD FindWoWProcess() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) { return 0; }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(snapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, PROCESS_NAME) == 0) {
                    CloseHandle(snapshot);
                    return pe32.th32ProcessID;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
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