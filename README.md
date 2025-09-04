# ETWsTrace
Proof of concept of a ETW (Event Tracing for Windows) consumer that shows what a specific process is doing.

The original idea was to print system calls executed from a specific process, somewhat like GNU strace does on linux, but ETW seems to lack of a producer that directly traces syscalls.

## Traced actions

### Microsoft Windows Kernel Process
GUID `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716`

- Thread Start (event 3): `[TID 14088] Thread start, created by TID 728, executing 0x7ffaca72afe0`
- Thread Stop (event 4): `[TID 14088] Thread stop`

