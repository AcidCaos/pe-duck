# PE-duck
A simple PE file parser.

## Usage

Usage: `pe <PE_EXEC>`

## Output

PE file (supports EXE and DLL, both 32 and 64 bit)
- DOS Header
- NT Header
    - File Header
        - Verbose Machine and Characteristics
        - Symbols
    - Optional Header (32 and 64 bit)
        - Verbose Subsystem and DllCharacteristics
        - Data Directories
            - IMAGE_DIRECTORY_ENTRY_EXPORT
                - DLL Exports (the DLL is not loaded, RVA translation is performed)
- Section Headers
    - Verbose Characteristics

## Build

Compile using [MSVC compiler](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax): `CL pe.c /Fe"pe.exe"`