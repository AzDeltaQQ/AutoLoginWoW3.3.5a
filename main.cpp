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
#include <cstddef> // For ptrdiff_t
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
    DWORD lastLoginStateCodeAddr; // Will hold the allocated address
    BYTE originalBytes[5];        // To store the original code for unhooking

public:
    static WoWAutoLogin* instance;

    // Declarations for moved member functions
    ConnectionStatus GetGlueErrorStatus();
    std::string ReadGlobalString(DWORD address, size_t maxSize);
    ClientState GetClientState();
    void ResetLoginState();
    bool HookLoginStateChange();
    bool UnhookLoginStateChange();
    int GetLastLoginStateCode();

    WoWAutoLogin(const std::string& account, const std::string& pass)
        : accountName(account), password(pass), isRunning(false), m_loginAttempted(false), lastState((ClientState)-1) {
        processHandle = NULL;
        processId = 0;
        lastLoginStateCodeAddr = 0;
        memset(originalBytes, 0, sizeof(originalBytes));
    }

    ~WoWAutoLogin() {
        if (processHandle) CloseHandle(processHandle);
        if (instance == this) instance = nullptr;
        UnhookLoginStateChange(); // Ensure unhooking on destruction
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
            stub.insert(stub.end(), (char*)&arg, (char*)&arg + (ptrdiff_t)sizeof(DWORD));
        }
        // mov eax, functionAddr
        stub.push_back(0xB8);
        stub.insert(stub.end(), (char*)&functionAddr, (char*)&functionAddr + (ptrdiff_t)sizeof(DWORD));
        // call eax
        stub.push_back(0xFF);
        stub.push_back(0xD0);
        // add esp, X (cdecl cleanup)
        if (!args.empty()) {
            stub.push_back(0x83); stub.push_back(0xC4); stub.push_back((BYTE)(args.size() * sizeof(DWORD)));
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
        stub.insert(stub.end(), (char*)&thisPtr, (char*)&thisPtr + (ptrdiff_t)sizeof(DWORD));
        // push arguments
        for (auto it = args.rbegin(); it != args.rend(); ++it) {
            stub.push_back(0x68); // PUSH
            DWORD arg = *it;
            stub.insert(stub.end(), (char*)&arg, (char*)&arg + (ptrdiff_t)sizeof(DWORD));
        }
        // mov eax, functionAddr
        stub.push_back(0xB8);
        stub.insert(stub.end(), (char*)&functionAddr, (char*)&functionAddr + (ptrdiff_t)sizeof(DWORD));
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
    
    void Run(const std::string& targetRealm) {
        if (!AttachToProcess()) return;
        isRunning = true;
        Log("Starting main loop. Target realm: '" + targetRealm + "'", "INFO");

        // --- Hook HandleLoginStateChange here ---
        if (!HookLoginStateChange()) {
            Log("Failed to hook HandleLoginStateChange. Continuing without hook logging.", "WARN");
        }

        auto actionTimer = std::chrono::steady_clock::now();
        bool realmSelectAttempted = false;

        while (isRunning) {
            ClientState currentState = GetClientState();
            
            // --- Log hooked state change if available ---
            int lastLoginCode = GetLastLoginStateCode();
            if (lastLoginCode != -1) {
                Log("Hook captured HandleLoginStateChange with code: " + std::to_string(lastLoginCode), "DEBUG");
                // Optionally, clear the stored code after reading if you only want to log new events
                // WriteProcessMemory(processHandle, (LPVOID)lastLoginStateCodeAddr, 0, sizeof(DWORD), NULL);
            }
            
            if (currentState != lastState) {
                Log("State changed to: " + StateToString(currentState), "STATE");
                lastState = currentState;
                actionTimer = std::chrono::steady_clock::now(); // Reset timer on any state change
            }

            switch (currentState) {
                case AT_LOGIN_SCREEN:
                    {
                        // Only try to log in if we haven't already.
                        // This prevents a loop of failures if credentials are bad.
                        if (!m_loginAttempted) {
                            Log("Client is at login screen. Initiating login.", "INFO");
                            InitiateLogin();
                            m_loginAttempted = true; // Mark that we've tried.
                            realmSelectAttempted = false;
                        }
                    }
                    break;

                case CONNECTING_TO_AUTH:
                case CONNECTING_TO_REALM:
                    {
                        Log("Waiting for connection...", "VERBOSE", true);
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - actionTimer).count();
                        if (elapsed > LOGIN_TIMEOUT) {
                            Log("Connection timed out. Resetting state.", "WARN");
                            ResetLoginState();
                            // Let the state machine transition naturally. It will either go to
                            // ERROR_STATE or back to AT_LOGIN_SCREEN where m_loginAttempted will prevent a loop.
                        }
                    }
                    break;

                case ERROR_STATE: {
                    ConnectionStatus status = GetGlueErrorStatus();
                    Log("Detected error state with ConnectionStatus: " + std::to_string(status), "ERROR");
                    
                    // First, dismiss the dialog. This also clears the global error variables.
                    // Your GlueMgr_HandleDisconnect (0x4DA9D0) is the correct function for this.
                    ResetLoginState();

                    // Now, handle the error code we captured BEFORE resetting.
                    switch (status) {
                        case RESPONSE_FAILED_TO_CONNECT:
                        case RESPONSE_DISCONNECTED:
                        case AUTH_LOGIN_SERVER_NOT_FOUND:
                            Log("Error: Server seems to be down. Retrying in " + std::to_string(RECONNECT_DELAY) + "s.", "WARN");
                            std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                            // Allow a new login attempt by resetting the flag.
                            m_loginAttempted = false; 
                            break;

                        case AUTH_INCORRECT_PASSWORD:
                        case AUTH_UNKNOWN_ACCOUNT:
                        case AUTH_BANNED:
                        case AUTH_SUSPENDED:
                            Log("Error: Unrecoverable account issue (Banned/Bad Pass/etc). Halting.", "FATAL");
                            isRunning = false;
                            break;
                            
                        default:
                            Log("Unhandled error (" + std::to_string(status) + "). Resetting and retrying after delay.", "WARN");
                            std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                            m_loginAttempted = false;
                            break;
                    }
                    // Break to allow the main loop to re-evaluate the (now reset) state immediately.
                    break;
                }
                
                case AUTH_SUCCESS:
                    Log("Authentication successful. Waiting for realm list...", "INFO");
                    m_loginAttempted = true; // Still in the login process.
                    break;

                case REALM_LIST:
                    {
                        if (!realmSelectAttempted) {
                            m_loginAttempted = false; // We're past the main login part.
                            Log("Realm list is ready. Selecting realm: '" + targetRealm + "'", "INFO");
                            std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // Small delay for UI to populate
                            if (!SelectRealm(targetRealm)) {
                                Log("Failed to select realm. Check realm name.", "FATAL");
                                isRunning = false;
                            }
                            realmSelectAttempted = true;
                        }
                    }
                    break;

                case CHARACTER_SELECT:
                    {
                        Log("Successfully logged in to character select. Monitoring.", "SUCCESS");
                        m_loginAttempted = false; 
                        realmSelectAttempted = false; // Reset for potential disconnect/relog
                        // You could stop the loop here, or monitor for disconnects.
                        std::this_thread::sleep_for(std::chrono::seconds(15)); // Monitor for a bit
                    }
                    break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        Log("Auto-login loop stopped.", "INFO");
        UnhookLoginStateChange(); // Cleanup
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

// Member function definitions outside the class
ConnectionStatus WoWAutoLogin::GetGlueErrorStatus() {
    return ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
}

std::string WoWAutoLogin::ReadGlobalString(DWORD address, size_t maxSize) {
    std::vector<char> buffer(maxSize);
    if (ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), maxSize, NULL)) {
        buffer[maxSize - 1] = '\0';
        return std::string(buffer.data());
    }
    return "";
}

ClientState WoWAutoLogin::GetClientState() {
    // Priority 1: Check for definitive success states using the UI state string.
    std::string stateStr = ReadGlobalString(GAME_STATE_STRING_ADDR, 64);
    if (stateStr == "charselect" || stateStr == "charcreate") {
        return CHARACTER_SELECT;
    }

    // Priority 2: Check for a "fast fail" error. This is the crucial fix.
    // This state occurs when we are on the login screen AND we have attempted a login.
    // In this case, the global error status is the most reliable source of truth.
    if (stateStr == "login" && m_loginAttempted) {
        ConnectionStatus errorStatus = ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
        if (errorStatus == RESPONSE_FAILED_TO_CONNECT || errorStatus == AUTH_LOGIN_SERVER_NOT_FOUND) {
            return ERROR_STATE;
        }
    }

    // Priority 3: Check the native CClientConnection object for in-progress or other error states.
    DWORD pClientConnection = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
    if (pClientConnection && pClientConnection != 0xFFFFFFFF) {
        ClientOperation op = ReadMemory<ClientOperation>(pClientConnection + CCLIENTCONNECTION_OPERATION_OFFSET);
        
        if (op == COP_FAILED) return ERROR_STATE;

        ConnectionStatus status = ReadMemory<ConnectionStatus>(pClientConnection + CCLIENTCONNECTION_STATUS_OFFSET);
        
        // Any authentication error is an immediate error state.
        if (op == COP_AUTHENTICATE && status > AUTH_OK && status != STATUS_NONE) {
            return ERROR_STATE;
        }
        
        switch (op) {
            case COP_CONNECT:
            case COP_HANDSHAKE:
                return CONNECTING_TO_AUTH;
            case COP_AUTHENTICATE:
                if (status == AUTH_OK) return AUTH_SUCCESS;
                return CONNECTING_TO_AUTH; // Still in the process
            case COP_GET_REALMS:
                if (status == REALM_LIST_SUCCESS) return REALM_LIST;
                return AUTH_SUCCESS; // Still downloading list
            case COP_LOGIN_CHARACTER:
                return CONNECTING_TO_REALM;
        }
    }

    // Priority 4: If all else fails and we are on the login screen, we are idle.
    if (stateStr == "login") {
        return AT_LOGIN_SCREEN;
    }
    
    // Fallback for any other unknown state.
    return AT_LOGIN_SCREEN;
}

void WoWAutoLogin::ResetLoginState() {
    Log("Calling reset function to dismiss dialog and clear state...", "ACTION");
    CallCdeclFunction(RESET_LOGIN_STATE_FUNC, {});
}

bool WoWAutoLogin::HookLoginStateChange() {
    // Step 1: Allocate memory to store the result code.
    lastLoginStateCodeAddr = AllocateRemoteMemory(sizeof(DWORD));
    if (!lastLoginStateCodeAddr) {
        Log("Failed to allocate memory for code storage.", "ERROR");
        return false;
    }
    // Initialize it to -1 (or some other invalid code)
    int initialCode = -1;
    WriteProcessMemory(processHandle, (LPVOID)lastLoginStateCodeAddr, &initialCode, sizeof(int), NULL);

    Log("Allocated code storage at 0x" + std::to_string(lastLoginStateCodeAddr), "INFO");

    // Step 2: Read the original bytes from the target function for restoration later.
    if (!ReadProcessMemory(processHandle, (LPCVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, originalBytes, 5, NULL)) {
        Log("Failed to read original bytes of HandleLoginStateChange.", "ERROR");
        return false;
    }

    // Assembly stub logic:
    //   mov eax, [esp+8]      ; Get the *second* argument (the login code). esp+4 is the 'this' ptr.
    //   mov [lastLoginStateCodeAddr], eax ; Store it in our allocated memory
    //   push ebp              ; Original instruction 1 (0x55)
    //   mov ebp, esp          ; Original instruction 2 (0x8B 0xEC)
    //   jmp back_to_original  ; Jump back to the rest of the function

    std::vector<BYTE> stub = {
        0x8B, 0x44, 0x24, 0x08,             // mov eax, [esp+8] (Corrected to get the int code, not the 'this' ptr)
        0xA3, 0x00, 0x00, 0x00, 0x00,       // mov [lastLoginStateCodeAddr], eax - Will patch this
        0x55,                               // push ebp (Original instruction 1)
        0x8B, 0xEC,                         // mov ebp, esp (Original instruction 2)
        0xE9, 0x00, 0x00, 0x00, 0x00        // jmp back_to_original - Will patch this
    };

    // Patch the address where we will store the code
    memcpy(&stub[5], &lastLoginStateCodeAddr, 4);

    // Allocate memory for the stub *before* calculating the relative jump
    DWORD stubAddr = AllocateRemoteMemory(stub.size());
    if (!stubAddr) {
        Log("Failed to allocate memory for the hook stub.", "ERROR");
        return false;
    }

    // Calculate the relative address for the jump back
    DWORD jmpBackAddr = HANDLE_LOGIN_STATE_CHANGE_FUNC + 5;
    DWORD relativeJmpBack = jmpBackAddr - (stubAddr + stub.size());
    memcpy(&stub[14], &relativeJmpBack, 4);

    // Write the NOW-PATCHED stub to memory
    if (!WriteProcessMemory(processHandle, (LPVOID)stubAddr, stub.data(), stub.size(), NULL)) {
        Log("Failed to write stub to memory.", "ERROR");
        FreeRemoteMemory(stubAddr);
        return false;
    }
    
    // Overwrite the original function with a jump to our stub
    BYTE jmpPatch[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    DWORD relativeAddr = stubAddr - (HANDLE_LOGIN_STATE_CHANGE_FUNC + 5);
    memcpy(&jmpPatch[1], &relativeAddr, 4);
    
    DWORD oldProtect;
    VirtualProtectEx(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    bool success = WriteProcessMemory(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, jmpPatch, 5, NULL);
    VirtualProtectEx(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, 5, oldProtect, &oldProtect);

    if (success) {
        Log("Successfully hooked HandleLoginStateChange.", "SUCCESS");
    } else {
        Log("Failed to write JMP patch to HandleLoginStateChange.", "ERROR");
    }
    return success;
}

bool WoWAutoLogin::UnhookLoginStateChange() {
    if (originalBytes[0] == 0) return true; // Nothing to unhook

    DWORD oldProtect;
    VirtualProtectEx(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    bool success = WriteProcessMemory(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, originalBytes, 5, NULL);
    VirtualProtectEx(processHandle, (LPVOID)HANDLE_LOGIN_STATE_CHANGE_FUNC, 5, oldProtect, &oldProtect);
    
    if (lastLoginStateCodeAddr) {
        FreeRemoteMemory(lastLoginStateCodeAddr);
        lastLoginStateCodeAddr = 0;
    }
    Log("Unhooked HandleLoginStateChange.", "INFO");
    return success;
}

int WoWAutoLogin::GetLastLoginStateCode() {
    if (!lastLoginStateCodeAddr) return -1; // Not hooked
    
    int code = ReadMemory<int>(lastLoginStateCodeAddr);
    
    // If we read a valid code, reset it so we don't log it again.
    if (code != -1) {
        int resetValue = -1;
        WriteProcessMemory(processHandle, (LPVOID)lastLoginStateCodeAddr, &resetValue, sizeof(int), NULL);
    }
    return code;
}

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