#pragma once

// The high-level internal function called by the UI's Lua script.
#define PROCESS_SERVER_LOGIN_FUNC 0x4D8A30

// Pointers and offsets needed AFTER login succeeds.
#define NETCLIENT_PTR_ADDR 0xC79CEC
#define CLIENTCONNECTION_PTR_ADDR 0xC79CE0
#define AUTH_STATUS_FLAG_OFFSET 0x2F18
#define PROCESS_BNET_AUTH_PACKET 0x8C80E0
#define VTABLE_RESET_OFFSET 0x84
#define REALM_COUNT_OFFSET 0x1144
#define REALM_LIST_PTR_OFFSET 0x1148
#define REALM_NAME_OFFSET 0x04
#define REALM_STRUCT_SIZE 0x104

// Program Settings
#define PROCESS_NAME "Project-Epoch.exe"
#define REALM_LIST_TIMEOUT 30
#define FUNCTION_CALL_TIMEOUT 15
#define DISCONNECT_CHECK_INTERVAL 1000
#define RECONNECT_DELAY 5
#define DEBUG_OUTPUT 1
#define VERBOSE_LOGGING 1

// Memory Protection
#define MEMORY_PROTECTION PAGE_EXECUTE_READWRITE 