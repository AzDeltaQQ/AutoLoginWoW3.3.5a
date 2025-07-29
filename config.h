#pragma once
#include <cstdint>

// --- Timers and Delays ---
#define LOGIN_TIMEOUT                   30  // seconds to wait in a connection state before recovering
#define RECONNECT_DELAY                 10  // seconds to wait after a recoverable error before retrying

// --- Core Game Functions ---
#define PROCESS_SERVER_LOGIN_FUNC       0x4D8A30 // Lua: DefaultServerLogin(account, password)
#define RESET_LOGIN_STATE_FUNC          0x4DA9D0 // Equivalent to clicking "Cancel" on any login/realm dialog.

// --- Global Pointers & State Variables ---
#define CLIENTCONNECTION_PTR_ADDR       0xC79CE0 // CClientConnection**
#define NETCLIENT_PTR_ADDR              0xC79CEC // CNetClient** (Note: CClientConnection inherits from this)
#define GLUE_LOGIN_STATE_ADDR           0xB6AFA0 // The g_LoginState enum (int)
#define GAME_STATE_STRING_ADDR          0xB6A9E0 // The current UI screen (char*) e.g., "login", "charselect"
#define IS_WORLD_LOADED_ADDR            0xBEBA40 // Set to 1 when in the 3D world (int)
#define GLUE_ERROR_OPERATION_ADDR       0xAC3DA4 // Stores the ClientOperation code of the last error.
#define GLUE_ERROR_STATUS_ADDR          0xAC3DA0 // Stores the ConnectionStatus code of the last error.

// --- Object Offsets ---
// CNetClient offsets (within CClientConnection)
#define REALM_COUNT_OFFSET              0x1144    // Correct per analysis of Grunt/Battle.net login
#define REALM_LIST_PTR_OFFSET           0x1148    // Correct per analysis

// RealmInfo struct offsets
#define REALM_NAME_OFFSET               0x04
#define REALM_STRUCT_SIZE               0x104

// CClientConnection offsets (most important)
#define CCLIENTCONNECTION_OPERATION_OFFSET  0x2F4C
#define CCLIENTCONNECTION_STATUS_OFFSET     0x2F50

// --- Program Settings ---
#define PROCESS_NAME                    "Project-Epoch.exe"
#define FUNCTION_CALL_TIMEOUT           5000      // Milliseconds
#define DEBUG_OUTPUT                    1
#define VERBOSE_LOGGING                 1

// --- Memory Protection ---
#define MEMORY_PROTECTION               PAGE_EXECUTE_READWRITE


// Represents the current high-level operation the client is performing.
// Derived from the string array at 0xAB95F0
enum ClientOperation {
    COP_NONE = 0,
    COP_INIT = 1,
    COP_CONNECT = 2,
    COP_HANDSHAKE = 3,
    COP_AUTHENTICATE = 4,
    COP_FAILED = 5,
    COP_DOWNLOADFILE = 6,
    COP_GET_CHARACTERS = 7, 
    COP_LOGIN_CHARACTER = 8,
    COP_GET_REALMS = 9,
    COP_AUTHENTICATED = 10,
    COP_WAIT_QUEUE = 11,
    COP_CHECKINGVERSIONS = 12,
    COP_PIN = 13,
    COP_PIN_WAIT = 14,
    COP_MATRIX = 15,
    COP_MATRIX_WAIT = 16,
    COP_TOKEN = 17,
    COP_TOKEN_WAIT = 18,
    COP_SURVEY = 19
};

// Represents the detailed status of the current operation.
// Derived from the string array at 0xAB9548 and cross-referenced with packet handlers.
enum ConnectionStatus {
    RESPONSE_SUCCESS = 0, RESPONSE_FAILURE = 1, RESPONSE_CANCELLED = 2,
    RESPONSE_DISCONNECTED = 3, RESPONSE_FAILED_TO_CONNECT = 4, RESPONSE_CONNECTED = 5,
    RESPONSE_VERSION_MISMATCH = 6, CSTATUS_CONNECTING = 7, CSTATUS_NEGOTIATING_SECURITY = 8,
    CSTATUS_NEGOTIATION_COMPLETE = 9, CSTATUS_NEGOTIATION_FAILED = 10, CSTATUS_AUTHENTICATING = 11,
    AUTH_OK = 12, AUTH_FAILED = 13, AUTH_REJECT = 14, AUTH_BAD_SERVER_PROOF = 15,
    AUTH_UNAVAILABLE = 16, AUTH_SYSTEM_ERROR = 17, AUTH_BILLING_ERROR = 18,
    AUTH_BILLING_EXPIRED = 19, AUTH_VERSION_MISMATCH_2 = 20, AUTH_UNKNOWN_ACCOUNT = 21,
    AUTH_INCORRECT_PASSWORD = 22, AUTH_SESSION_EXPIRED = 23, AUTH_SERVER_SHUTTING_DOWN = 24,
    AUTH_ALREADY_LOGGING_IN = 25, AUTH_LOGIN_SERVER_NOT_FOUND = 26, AUTH_WAIT_QUEUE = 27,
    AUTH_BANNED = 28, AUTH_ALREADY_ONLINE = 29, AUTH_NO_TIME = 30, AUTH_DB_BUSY = 31,
    AUTH_SUSPENDED = 32, AUTH_PARENTAL_CONTROL = 33, AUTH_LOCKED_ENFORCED = 34,
    REALM_LIST_IN_PROGRESS = 35, REALM_LIST_SUCCESS = 36, REALM_LIST_FAILED = 37,
    REALM_LIST_INVALID = 38, REALM_LIST_REALM_NOT_FOUND = 39, ACCOUNT_CONVERTED = 40,
    CHAR_CREATE_IN_PROGRESS = 41,
    CHAR_CREATE_SUCCESS = 42,
    CHAR_CREATE_FAILED = 43,
    CHAR_CREATE_NAME_IN_USE = 44,
    CHAR_CREATE_DISABLED = 45,
    STATUS_NONE = 0xFFFFFFFF
};

// Note: CNetClient is the base class. Its size is 0x2EE0 based on the first member of CClientConnection.
// We don't need its full definition for this task.

struct CharacterInfo {
    uint64_t guid;                       // +0x00
    char     name[48];                   // +0x08
    uint8_t  race;                       // +0x38
    uint8_t  classId;                    // +0x39
    uint8_t  gender;                     // +0x3A
    uint8_t  skin;                       // +0x3B
    uint8_t  face;                       // +0x3C
    uint8_t  hairStyle;                  // +0x3D
    uint8_t  hairColor;                  // +0x3E
    uint8_t  facialHair;                 // +0x3F
    uint8_t  level;                      // +0x40
    uint32_t zoneId;                     // +0x44
    uint32_t mapId;                      // +0x48
    float    x;                          // +0x4C
    float    y;                          // +0x50
    float    z;                          // +0x54
    uint32_t guildId;                    // +0x58
    // ... data continues for 0x188 bytes total
};

class CClientConnection {
public:
    // CNetClient part of the object (size 0x2EE0)
    char CNetClient_Data[0x2EE0];

    // CClientConnection specific members
    void*           m_pClientServices;          // +0x2EE0
    uint32_t        m_realmSplitState[10];      // +0x2EE4
    
    // Character List Data
    uint32_t        m_characterCount;           // +0x2F0C
    CharacterInfo*  m_characterList;            // +0x2F10
    uint32_t        m_characterListCapacity;    // +0x2F14

    // Authentication & State
    bool            m_isAuthenticated;          // +0x2F18
    uint32_t        m_queuePosition;            // +0x2F1C
    bool            m_hasFreeCharacterMigration;// +0x2F20
    
    // Billing Info from SMSG_AUTH_RESPONSE
    uint32_t        m_billingTimeRemaining;     // +0x2F24
    uint32_t        m_billingTimeRested;        // +0x2F28
    uint8_t         m_billingFlags;             // +0x2F2C
    uint8_t         m_accountExpansion;         // +0x2F2D (0=Classic, 1=TBC, 2=WotLK)

    // Other Client State
    uint32_t        m_clientCacheVersion;       // +0x2F30
    uint32_t        m_unknown_2F34;             // +0x2F34
    uint32_t        m_unknown_2F38;             // +0x2F38
    uint32_t        m_connectionFlags;          // +0x2F3C (Bitflags related to connection type)

    // *** CRITICAL STATE FIELDS ***
    ClientOperation m_currentOperation;         // +0x2F4C
    ConnectionStatus m_currentStatus;           // +0x2F50
    
    uint32_t        m_unknownState1;            // +0x2F54
    bool            m_isLoggingOut;             // +0x2F58
    bool            m_isDisconnected;           // +0x2F59
}; 
