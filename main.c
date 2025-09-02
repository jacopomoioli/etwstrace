#include <stdio.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

typedef struct {
    EVENT_TRACE_PROPERTIES properties;
    char session_name[64];
} ETW_SESSION_CONFIG;

/*
 *  Windows Kernel Trace ETW producer GUID
 *  PS command to list all providers: logman query providers
 */
static const GUID KERNEL_PROVIDER_GUID = {0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

static const GUID DNS_CLIENT_GUID = {0x1c95126e, 0x7eea, 0x49a9, {0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d}};

/*
 *  Kernel provider system call keyword
 *  PS command to list all keyword of a provider: logman query providers "{9E814AAD-3204-11D2-9A82-006008A86939}"
 */
static const int SYSCALL_KEYWORD = 0x0000000000000001;

static const int ALL_KEYWORD = 0xFFFFFFFFFFFFFFFF;


void WINAPI event_callback(PEVENT_RECORD event_record) {
    printf("[+] Syscall event received\n");
}

int main(int argc, char** argv){
    ETW_SESSION_CONFIG config = {0};
    TRACEHANDLE session_handle = 0;
    
    // Session config setup
    config.properties.Wnode.BufferSize = sizeof(ETW_SESSION_CONFIG);
    config.properties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    config.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    strcpy(config.session_name, "ETWsTrace");

    // Session creation
    ULONG result = StartTraceA(&session_handle, config.session_name, &config.properties);
    
    if (result != ERROR_SUCCESS) {
        printf("[!] Failed to start ETW session: %lu\n", result);
        return 1;
    }

    // Enable kernel provider
    result = EnableTraceEx2(
        session_handle,
        &DNS_CLIENT_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        NULL
    );

    if (result != ERROR_SUCCESS){
        printf("[!] Failed to enable producer \"kernel provider\"\n");
        return 1;
    } 

    // Tracing config setup
    EVENT_TRACE_LOGFILE trace_logfile = {0};
    trace_logfile.LoggerName = config.session_name;
    trace_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)event_callback;
    trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;


    // Open ETW tracing handle in order to consume produced events
    TRACEHANDLE trace_handle = OpenTrace(&trace_logfile);
    if (trace_handle == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open trace\n");
        return 1;
    }

    ProcessTrace(&trace_handle, 1, 0, 0);

    return 0;
}