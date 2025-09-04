# ETWsTrace
Proof of concept of a ETW (Event Tracing for Windows) consumer that shows what a specific process is doing.

The original idea was to print system calls executed from a specific process, somewhat like GNU strace does on linux, but ETW seems to lack of a producer that directly traces syscalls.

## Traced actions

### Microsoft Windows Kernel Process
GUID `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716`

- Thread Start (event 3): `[TID 14088] Thread start, created by TID 728, executing 0x7ffaca72afe0`
- Thread Stop (event 4): `[TID 14088] Thread stop`

## Build
In order to build the project is enough to run 
```bash
cc main.c -o main.exe
```
via Msys2 (tested using CLANGARM64)

## Acknowledgements

- Pavel Yosifovch for creating [ETW Explorer](https://github.com/zodiacon/EtwExplorer), useful to avoid the hot garbage that the official documentation about ETW providers is