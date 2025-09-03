#include <stdio.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>
#include <tdh.h>

typedef struct {
    EVENT_TRACE_PROPERTIES properties;
    char session_name[64];
} ETW_SESSION_CONFIG;

/*
 *  Windows Kernel Trace ETW producer GUID
 *  PS command to list all providers: logman query providers
 */
static const GUID KERNEL_PROVIDER_GUID = {0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};

static const GUID KERNEL_AUDIT_API_CALLS_GUID = {0xe02a841c, 0x75a3, 0x4fa7, {0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}}; // E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23

static const GUID KERNEL_PROCESS_PROVIDER_GUID = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

/*
*  Kernel provider system call keyword
*  PS command to list all keyword of a provider: logman query providers "{9E814AAD-3204-11D2-9A82-006008A86939}"
 */
static const int SYSCALL_KEYWORD = 0x0000000000000001;

static ULONG target_pid;


void WINAPI event_callback(PEVENT_RECORD event_record) {
    if(event_record->EventHeader.ProcessId != target_pid){
        return;
    }

    printf(
        "[+] Event ID: %d, PID: %lu, TID: %lu\n",
        event_record->EventHeader.EventDescriptor.Id,
        event_record->EventHeader.ProcessId,
        event_record->EventHeader.ThreadId
    );

    
}

int main(int argc, char** argv){
    ETW_SESSION_CONFIG config = {0};
    TRACEHANDLE session_handle = 0;

    // Get target pid from argv
    target_pid = atoi(argv[1]);
    
    // Session config setup
    config.properties.Wnode.BufferSize = sizeof(ETW_SESSION_CONFIG);
    config.properties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    config.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    strcpy(config.session_name, "ETWsTrace");

   
    // Stop previous traces
    ControlTrace(0, config.session_name, &config.properties, EVENT_TRACE_CONTROL_STOP);

    // Session creation
    ULONG result = StartTraceA(&session_handle, config.session_name, &config.properties);
    
    switch(result) {
        case ERROR_SUCCESS:
            break;
        default:
            printf("[!] Failed to start ETW session: %lu\n", result);
            return 1;
    }

    // Enable provider
    result = EnableTraceEx2(
        session_handle,
        &KERNEL_AUDIT_API_CALLS_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,
        0,
        0,
        NULL
    );

    if (result != ERROR_SUCCESS){
        printf("[!] Failed to enable producer: error %d\n", result);
        return 1;
    } 

    // Tracing config setup
    EVENT_TRACE_LOGFILE trace_logfile = {0};
    trace_logfile.LoggerName = config.session_name;
    trace_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)event_callback;
    trace_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;


    TRACEHANDLE trace_handle = OpenTrace(&trace_logfile);
    if (trace_handle == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open trace\n");
        return 1;
    }

    ProcessTrace(&trace_handle, 1, 0, 0);

    return 0;
}