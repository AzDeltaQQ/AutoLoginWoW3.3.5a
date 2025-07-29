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
    std::chrono::steady_clock::time_point m_loginAttemptTime; // Timestamp of last login attempt
    Logger logger;
    ClientState lastState;

public:
    static WoWAutoLogin* instance;

    // Declarations for moved member functions
    ConnectionStatus GetGlueErrorStatus();
    std::string ReadGlobalString(DWORD address, size_t maxSize);
    ClientState GetClientState();
    ConnectionStatus GetDetailedErrorStatus();
    void ResetLoginState();

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

    void LogAllGlobalVariables() {
        Log("=== Reading All Global Variables ===", "DEBUG");
        
        // Read and log all global variables
        DWORD clientConnectionPtr = ReadMemory<DWORD>(CLIENTCONNECTION_PTR_ADDR);
        std::stringstream ss;
        ss << "Read CLIENTCONNECTION_PTR at 0x" << std::hex << CLIENTCONNECTION_PTR_ADDR << " = 0x" << std::hex << clientConnectionPtr;
        Log(ss.str(), "MEMORY", true);
        
        DWORD netClientPtr = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
        ss.str("");
        ss << "Read NETCLIENT_PTR at 0x" << std::hex << NETCLIENT_PTR_ADDR << " = 0x" << std::hex << netClientPtr;
        Log(ss.str(), "MEMORY", true);
        
        int glueLoginState = ReadMemory<int>(GLUE_LOGIN_STATE_ADDR);
        ss.str("");
        ss << "Read GLUE_LOGIN_STATE at 0x" << std::hex << GLUE_LOGIN_STATE_ADDR << " = " << std::dec << glueLoginState;
        Log(ss.str(), "MEMORY", true);
        
        std::string gameStateStr = ReadGlobalString(GAME_STATE_STRING_ADDR, 64);
        ss.str("");
        ss << "Read GAME_STATE_STRING at 0x" << std::hex << GAME_STATE_STRING_ADDR << " = '" << gameStateStr << "'";
        Log(ss.str(), "MEMORY", true);
        
        int isWorldLoaded = ReadMemory<int>(IS_WORLD_LOADED_ADDR);
        ss.str("");
        ss << "Read IS_WORLD_LOADED at 0x" << std::hex << IS_WORLD_LOADED_ADDR << " = " << std::dec << isWorldLoaded;
        Log(ss.str(), "MEMORY", true);
        
        ClientOperation glueErrorOp = ReadMemory<ClientOperation>(GLUE_ERROR_OPERATION_ADDR);
        ss.str("");
        ss << "Read GLUE_ERROR_OPERATION at 0x" << std::hex << GLUE_ERROR_OPERATION_ADDR << " = " << std::dec << glueErrorOp;
        Log(ss.str(), "MEMORY", true);
        
        ConnectionStatus glueErrorStatus = ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
        ss.str("");
        ss << "Read GLUE_ERROR_STATUS at 0x" << std::hex << GLUE_ERROR_STATUS_ADDR << " = " << std::dec << glueErrorStatus;
        Log(ss.str(), "MEMORY", true);
        
        int isLoginOperationPending = ReadMemory<int>(GLUE_IS_LOGIN_OPERATION_PENDING_ADDR);
        ss.str("");
        ss << "Read GLUE_IS_LOGIN_OPERATION_PENDING at 0x" << std::hex << GLUE_IS_LOGIN_OPERATION_PENDING_ADDR << " = " << std::dec << isLoginOperationPending;
        Log(ss.str(), "MEMORY", true);
        
        Log("=== End Global Variables ===", "DEBUG");
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
            ss << "Server is down - cannot read memory at address 0x" << std::hex << address;
            Log(ss.str(), "VERBOSE", true);
        }
        return value;
    }

    template<typename T>
    T ReadMemoryWithLog(DWORD address, const std::string& varName) {
        T value = ReadMemory<T>(address);
        std::stringstream ss;
        ss << "Read " << varName << " at 0x" << std::hex << address << " = ";
        
        if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, char*>) {
            ss << "'" << value << "'";
        } else if constexpr (std::is_same_v<T, bool>) {
            ss << (value ? "true" : "false");
        } else if constexpr (std::is_same_v<T, float>) {
            ss << std::fixed << std::setprecision(2) << value;
        } else {
            ss << std::dec << value << " (0x" << std::hex << value << ")";
        }
        
        Log(ss.str(), "MEMORY", true);
        return value;
    }

    template<typename T>
    bool WriteMemory(DWORD address, const T& value) {
        bool success = WriteProcessMemory(processHandle, (LPVOID)address, &value, sizeof(T), NULL);
        if (!success) {
            std::stringstream ss;
            ss << "Failed to write memory at address 0x" << std::hex << address << " (Error: " << std::dec << GetLastError() << ")";
            Log(ss.str(), "ERROR", true);
        }
        return success;
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
        
        // Set the login attempt timestamp
        m_loginAttemptTime = std::chrono::steady_clock::now();
        return success;
    }

    void Run(const std::string& targetRealm) {
        if (!AttachToProcess()) return;
        isRunning = true;
        Log("Starting main loop.", "INFO");

        auto actionTimer = std::chrono::steady_clock::now();
        bool realmSelectAttempted = false;

        while (isRunning) {
            // Log all global variables every 10 seconds for debugging
            static auto lastGlobalVarLog = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastGlobalVarLog).count() >= 10) {
                LogAllGlobalVariables();
                lastGlobalVarLog = now;
            }
            
            ClientState currentState = GetClientState();
            
            if (currentState != lastState) {
                Log("State changed to: " + StateToString(currentState), "STATE");
                lastState = currentState;
                actionTimer = std::chrono::steady_clock::now();
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
                    // Server is down - detected by stuck s_netClient state
                    Log("Server is down. Retrying in " + std::to_string(RECONNECT_DELAY) + "s.", "WARN");
                    
                    ResetLoginState(); // Dismiss any error dialogs
                    std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
                    m_loginAttempted = false; // Allow a new attempt
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
                            Log("Realm list is ready.", "INFO");
                            std::this_thread::sleep_for(std::chrono::milliseconds(1500)); // Small delay for UI to populate
                            // Realm selection removed - no Lua scripting
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
    ConnectionStatus status = ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
    std::stringstream ss;
    ss << "Read GLUE_ERROR_STATUS at 0x" << std::hex << GLUE_ERROR_STATUS_ADDR << " = " << std::dec << status;
    Log(ss.str(), "MEMORY", true);
    return status;
}

std::string WoWAutoLogin::ReadGlobalString(DWORD address, size_t maxSize) {
    std::vector<char> buffer(maxSize);
    if (ReadProcessMemory(processHandle, (LPCVOID)address, buffer.data(), maxSize, NULL)) {
        buffer[maxSize - 1] = '\0';
        std::string result = std::string(buffer.data());
        std::stringstream ss;
        ss << "Read global string at 0x" << std::hex << address << " = '" << result << "'";
        Log(ss.str(), "MEMORY", true);
        return result;
    }
    std::stringstream ss;
    ss << "Failed to read global string at 0x" << std::hex << address;
    Log(ss.str(), "MEMORY", true);
    return "";
}

ClientState WoWAutoLogin::GetClientState() {
    // Priority 1: Check for definitive success states.
    std::string stateStr = ReadGlobalString(GAME_STATE_STRING_ADDR, 64);
    if (stateStr == "charselect" || stateStr == "charcreate") {
        return CHARACTER_SELECT;
    }

    // Priority 2: Check for a specific error dialog being shown by the Glue Manager.
    // This is the most reliable way to detect "Unable to connect", "Disconnected", etc.
    ClientOperation glueErrorOp = ReadMemory<ClientOperation>(GLUE_ERROR_OPERATION_ADDR);
    if (glueErrorOp == COP_FAILED) {
        Log("Detected error state via GLUE_ERROR_OPERATION.", "VERBOSE", true);
        return ERROR_STATE;
    }

    // Priority 3: Check the s_netClient object for in-progress operations.
    DWORD pNetClient = ReadMemory<DWORD>(NETCLIENT_PTR_ADDR);
    
    // Server down detection: If we can't read the network client pointer or it's invalid
    if (!pNetClient || pNetClient < 0x1000000 || pNetClient > 0x7FFFFFFF) {
        if (m_loginAttempted) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_loginAttemptTime).count();
            
            if (elapsed > 3000) { // Wait 3 seconds before declaring server down
                Log("Server down detected: Invalid NETCLIENT_PTR (0x" + std::to_string(pNetClient) + ") after " + std::to_string(elapsed) + "ms", "INFO");
                return ERROR_STATE;
            } else {
                Log("Ignoring invalid NETCLIENT_PTR: 0x" + std::to_string(pNetClient) + " (only " + std::to_string(elapsed) + "ms since login)", "VERBOSE", true);
            }
        }
        return AT_LOGIN_SCREEN; // Can't determine state, assume login screen
    }
    
    // Try to read the operation and status
    ClientOperation op = ReadMemory<ClientOperation>(pNetClient + CCLIENTCONNECTION_OPERATION_OFFSET);
    ConnectionStatus status = ReadMemory<ConnectionStatus>(pNetClient + CCLIENTCONNECTION_STATUS_OFFSET);

    // Server down detection: Check for garbage memory values ONLY if a login was attempted.
    if (m_loginAttempted && (op < 0 || op > 100)) { // A more reasonable range check.
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_loginAttemptTime).count();
        
        if (elapsed > 3000) { // Wait 3 seconds before declaring server down
            Log("Server down detected: Garbage ClientOperation value: " + std::to_string(op) + " after " + std::to_string(elapsed) + "ms", "INFO");
            return ERROR_STATE;
        } else {
            Log("Ignoring garbage ClientOperation value: " + std::to_string(op) + " (only " + std::to_string(elapsed) + "ms since login)", "VERBOSE", true);
        }
    }

    // Check for normal progress states.
    switch (op) {
        case COP_CONNECT:
        case COP_HANDSHAKE:
        case COP_AUTHENTICATE:
            return CONNECTING_TO_AUTH;
        case COP_AUTHENTICATED:
            return AUTH_SUCCESS;
        case COP_GET_REALMS:
            return REALM_LIST;
        case COP_LOGIN_CHARACTER:
            return CONNECTING_TO_REALM;
    }
    
    // Fallback: If nothing else is detected, we are at the login screen.
    return AT_LOGIN_SCREEN;
}

ConnectionStatus WoWAutoLogin::GetDetailedErrorStatus() {
    // First, check the global UI error variable. This is often set for dialogs.
    ConnectionStatus glueError = ReadMemory<ConnectionStatus>(GLUE_ERROR_STATUS_ADDR);
    std::stringstream ss;
    ss << "Read GLUE_ERROR_STATUS at 0x" << std::hex << GLUE_ERROR_STATUS_ADDR << " = " << std::dec << glueError;
    Log(ss.str(), "MEMORY", true);
    
    if (glueError != STATUS_NONE && glueError >= 0) {
        return glueError;
    }

    // If that's not set, check the s_netClient object's internal status.
    DWORD pNetClient = ReadMemoryWithLog<DWORD>(NETCLIENT_PTR_ADDR, "NETCLIENT_PTR");
    if (pNetClient) { // Try to read from the pointer regardless
        ClientOperation op = ReadMemory<ClientOperation>(pNetClient + CCLIENTCONNECTION_OPERATION_OFFSET);
        ConnectionStatus status = ReadMemory<ConnectionStatus>(pNetClient + CCLIENTCONNECTION_STATUS_OFFSET);
        
        // Log the operation and status reads
        std::stringstream ss;
        ss << "Read ClientOperation at 0x" << std::hex << (pNetClient + CCLIENTCONNECTION_OPERATION_OFFSET) << " = " << std::dec << op;
        Log(ss.str(), "MEMORY", true);
        
        ss.str("");
        ss << "Read ConnectionStatus at 0x" << std::hex << (pNetClient + CCLIENTCONNECTION_STATUS_OFFSET) << " = " << std::dec << status;
        Log(ss.str(), "MEMORY", true);
        
        if (op == COP_FAILED) {
            return status;
        }
        
        // NEW: Handle the stuck state where op = 0 with garbage status
        if (op == COP_NONE) {
            ConnectionStatus status = ReadMemory<ConnectionStatus>(pNetClient + CCLIENTCONNECTION_STATUS_OFFSET);
            if (status > 1000) {
                // This is the "Unable to connect" failure pattern
                return RESPONSE_FAILED_TO_CONNECT;
            }
        }
        
        // NEW: Handle the server-down pattern where op is garbage
        if (op > 1000) {
            ConnectionStatus status = ReadMemory<ConnectionStatus>(pNetClient + CCLIENTCONNECTION_STATUS_OFFSET);
            if (status == 0) {
                // This is the server-down failure pattern
                return RESPONSE_FAILED_TO_CONNECT;
            }
        }
    }

    // If we are in an error state but have no code, it's the inferred "stuck" state.
    // Default to a generic connection failure.
    return RESPONSE_FAILED_TO_CONNECT;
}

void WoWAutoLogin::ResetLoginState() {
    Log("Calling reset function to dismiss dialog and clear state...", "ACTION");

    // --- STEP 1: Clean up the C++ and Network Backend ---
    Log("Forcing g_LoginState to 1 for backend cleanup.", "VERBOSE", true);
    if (!WriteMemory<int>(GLUE_LOGIN_STATE_ADDR, 1)) {
        Log("Failed to write to g_LoginState, cancellation may fail.", "ERROR");
    }
    // Call the original cancel function. We don't need to wait for it.
    CallCdeclFunction(RESET_LOGIN_STATE_FUNC, {});
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Give it a moment to start.

    // --- STEP 2: Force the Lua UI to Reset ---
    Log("Forcing UI reset by signaling SET_GLUE_SCREEN event.", "VERBOSE", true);
    
    // We need to pass the string "login" to the function.
    // To do this, we must allocate memory for it inside the WoW process.
    const char* screenName = "login";
    DWORD remoteStringAddr = AllocateRemoteMemory(strlen(screenName) + 1);
    if (!remoteStringAddr) {
        Log("Failed to allocate memory for screen name string.", "ERROR");
        m_loginAttempted = false;
        return;
    }

    if (!WriteString(remoteStringAddr, screenName)) {
        Log("Failed to write screen name string to remote memory.", "ERROR");
        FreeRemoteMemory(remoteStringAddr);
        m_loginAttempted = false;
        return;
    } else {
        Log("Successfully wrote 'login' string to remote memory at 0x" + std::to_string(remoteStringAddr), "VERBOSE", true);
    }

    // Now, call FrameScript_SignalEvent(0, "%s", remoteStringAddr)
    // Event 0 = "SET_GLUE_SCREEN"
    // %s = format specifier
    // remoteStringAddr = pointer to our "login" string
    DWORD formatStringAddr = FORMAT_STRING_S_ADDR; // Use the definition from config.h
    Log("Calling FrameScript_SignalEvent(0, 0x" + std::to_string(formatStringAddr) + ", 0x" + std::to_string(remoteStringAddr) + ")", "VERBOSE", true);
    
    bool success = CallCdeclFunction(FRAME_SCRIPT_SIGNAL_EVENT_FUNC, { 0, formatStringAddr, remoteStringAddr });
    if (!success) {
        Log("Call to FrameScript_SignalEvent FAILED.", "ERROR");
    } else {
        Log("Call to FrameScript_SignalEvent SUCCESSFUL.", "VERBOSE", true);
    }

    // Clean up the memory we allocated.
    FreeRemoteMemory(remoteStringAddr);
    
    // Give the UI a brief moment to execute the screen change.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Now, we can safely allow a new login attempt.
    m_loginAttempted = false;
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
    
    // Log credentials to console only (not to file)
    std::cout << "[CONSOLE] Account: " << account << std::endl;
    std::cout << "[CONSOLE] Realm: " << realm << std::endl;
    
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