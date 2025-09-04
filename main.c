#include <stdio.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>
#include <tdh.h>

/* ETW session configuration struct*/
typedef struct {
    EVENT_TRACE_PROPERTIES properties;
    char session_name[64];
} ETW_SESSION_CONFIG;

/* Windows kernel process provider event data */

/* ThreadStart (3) event data*/
typedef struct {
    ULONG ProcessId;
    ULONG ThreadId;
    ULONG64 StackBase;
    ULONG64 StackLimit;
    ULONG64 UserStackBase;
    ULONG64 UserStackLimit;
    ULONG64 StartAddr;
    ULONG64 Win32StartAddr;
    ULONG64 TebBase;
    ULONG SubProcessTag;
} THREAD_START_DATA;

/*
 *  Windows Kernel Process ETW producer GUID
 *  PS command to list all providers: logman query providers
 */
static const GUID KERNEL_PROCESS_PROVIDER_GUID = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};

static ULONG target_pid;


void WINAPI event_callback(PEVENT_RECORD event_record) {
    if(event_record->EventHeader.ProcessId != target_pid){
        return;
    }

    switch(event_record->EventHeader.EventDescriptor.Id){
        case 7:
        case 8:
        case 9:
        case 21:
        case 5:
        case 6:
            return;
        case 3:
            // Thread start
            THREAD_START_DATA* data = (THREAD_START_DATA*)event_record->UserData;
            printf("[TID %lu] Thread start, created by TID %lu, executing 0x%llx\n", data->ThreadId, event_record->EventHeader.ThreadId, data->Win32StartAddr);
            break;
        case 4:
            // Thread stop
            printf("[TID %lu] Thread stop\n", event_record->EventHeader.ThreadId);
            break;
        default:
            printf("[TID %lu] Unknown (Event %lu)\n", event_record->EventHeader.ThreadId, event_record->EventHeader.EventDescriptor.Id);
    }
}

int main(int argc, char** argv){
    ETW_SESSION_CONFIG config = {0};
    TRACEHANDLE session_handle = 0;

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
        &KERNEL_PROCESS_PROVIDER_GUID,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF, // all keywords
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