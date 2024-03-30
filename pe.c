#include <stdio.h> // sprintf
#include <stdint.h> // uint32_t, uint64_t
#include <Windows.h>
// #include <WinNT.h> // IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER, etc.
#include <errhandlingapi.h> // GetLastError

#include "pe.h"

#define VERSION "v0.3"

// Global pointers

char* _Image = 0;
IMAGE_DOS_HEADER* _DOSHeader = 0;
IMAGE_NT_HEADERS* _NTHeader = 0;
IMAGE_FILE_HEADER* _FileHeader = 0;
char* _OptionalHeader = 0;
IMAGE_SECTION_HEADER* _SectionTable = 0;

// Helper functions

void ErrorExit(wchar_t* name){
    uint32_t err_code = GetLastError();
    TCHAR* formattedStringBuffer = NULL;

    // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-formatmessage
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &formattedStringBuffer,
        0,
        NULL
    );

    wprintf(L"Error at %s (%d): %sBye!", (wchar_t*) name, err_code, (wchar_t*) formattedStringBuffer);
    LocalFree(formattedStringBuffer); // Free the allocated buffer
    exit(err_code);
}

void PrintStringLen(char* String, int Length){
    char* NullEndedString = (char*) malloc((Length + 1) * sizeof(char));
    strncpy(NullEndedString, String, Length);
    strncpy(NullEndedString + Length, "\0", 1);
    printf("%s", NullEndedString);
    free(NullEndedString);
}

void PrintWideStringLen(wchar_t* WString, int Length){
    wchar_t* NullEndedWString = (wchar_t*) malloc((Length + 1) * sizeof(wchar_t));
    wcsncpy(NullEndedWString, WString, Length);
    wcsncpy(NullEndedWString + Length, L"\0", 1);
    wprintf(L"%s", NullEndedWString);
    free(NullEndedWString);
}

char* OpenReadFile(char* Path) {
    printf("[+] Load PE file\r\n");
    printf(" * File: %s\r\n", Path);

    OFSTRUCT ofstruct = {0};
    HFILE HFile = OpenFile(Path, &ofstruct, OF_READ);
    if (!HFile || HFile < 0) ErrorExit(L"OpenFile");
    printf(" * File Handle (HFILE): %d\r\n", (int)HFile);

    uint32_t ReadBytes;
    uint64_t BufferSize = 0;

    BufferSize = GetFileSize(HFile, (uint32_t*) &BufferSize);
    if (!BufferSize || BufferSize < 0) ErrorExit(L"GetFileSize");
    printf(" * File size: %lld\r\n", BufferSize);
    
    char* Buffer = (char*) malloc(BufferSize * sizeof(char));
    if (!Buffer || Buffer == NULL) ErrorExit(L"malloc");

    BOOL Flag = ReadFile(HFile, Buffer, BufferSize, &ReadBytes, NULL);
    if (!Flag) ErrorExit(L"ReadFile");
    if (ReadBytes != BufferSize) ErrorExit(L"ReadFile (not fully read)");
    printf(" * Bytes read: %d\r\n", ReadBytes);

    return Buffer;
}

// RVA helper functions

uint32_t RelativeVirtualAddressToImageOffset(uint32_t VirtualAddress, IMAGE_DOS_HEADER* DOSHeader, IMAGE_FILE_HEADER* FileHeader, char* Image) {

    if(VirtualAddress == 0) return 0;

    IMAGE_NT_HEADERS* NTHeader = (IMAGE_NT_HEADERS*) (Image + DOSHeader->e_lfanew);
    IMAGE_SECTION_HEADER* SectionTable = (IMAGE_SECTION_HEADER*)((char*) NTHeader + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + NTHeader->FileHeader.SizeOfOptionalHeader);

    uint16_t i;
    for (i = 0; i < FileHeader->NumberOfSections; i++) {
        if ((SectionTable->VirtualAddress <= VirtualAddress) && (VirtualAddress < (SectionTable->VirtualAddress + SectionTable->Misc.VirtualSize)))
            break;
        SectionTable++;
    }
    if (i >= FileHeader->NumberOfSections) {
        printf("Error: section not found for VA=0x%x\r\n", VirtualAddress);
        exit(1);
        return 0;
    }
    return (uint32_t) ((uint32_t) SectionTable->PointerToRawData + (VirtualAddress - SectionTable->VirtualAddress));
}

char* RelativeVirtualAddressToRawAddress(uint32_t VirtualAddress, IMAGE_DOS_HEADER* DOSHeader, IMAGE_FILE_HEADER* FileHeader, char* Image) {
    return (char*)(Image + RelativeVirtualAddressToImageOffset(VirtualAddress, DOSHeader, FileHeader, Image));
}

// PE functions

void PrintDOSHeader(IMAGE_DOS_HEADER* DOSHeader) {

    if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("\r\n[!] Error: Could not find DOS signature.\r\n");
        exit(1);
    }

    printf("\r\n[+] DOS header\r\n");
    printf(" * Magic number: 0x%x\r\n", DOSHeader->e_magic);
    printf(" * Bytes on last page of file: 0x%x\r\n", DOSHeader->e_cblp);
    printf(" * Pages in file: 0x%x\r\n", DOSHeader->e_cp);
    printf(" * Relocations: 0x%x\r\n", DOSHeader->e_crlc);
    printf(" * Size of header in paragraphs: 0x%x\r\n", DOSHeader->e_cparhdr);
    printf(" * Minimum extra paragraphs needed: 0x%x\r\n", DOSHeader->e_minalloc);
    printf(" * Maximum extra paragraphs needed: 0x%x\r\n", DOSHeader->e_maxalloc);
    printf(" * Initial (relative) SS value: 0x%x\r\n", DOSHeader->e_ss);
    printf(" * Initial SP value: 0x%x\r\n", DOSHeader->e_sp);
    printf(" * Checksum: 0x%x\r\n", DOSHeader->e_csum);
    printf(" * Initial IP value: 0x%x\r\n", DOSHeader->e_ip);
    printf(" * Initial (relative) CS value: 0x%x\r\n", DOSHeader->e_cs);
    printf(" * File address of relocation table: 0x%x\r\n", DOSHeader->e_lfarlc);
    printf(" * Overlay number: 0x%x\r\n", DOSHeader->e_ovno);
    printf(" * OEM identifier (for e_oeminfo): 0x%x\r\n", DOSHeader->e_oemid);
    printf(" * OEM information; e_oemid specific: 0x%x\r\n", DOSHeader->e_oeminfo);
    printf(" * File address of new exe header: 0x%x\r\n", DOSHeader->e_lfanew);
}

// DataDirectory: Entry Export

void PrintDataDirectoryEntryExport(IMAGE_EXPORT_DIRECTORY* ExportDirectory) {

    printf("\r\n[+] Export Directory\r\n");

    printf(" * NumberOfFunctions: %d\r\n", ExportDirectory->NumberOfFunctions);
    printf(" * NumberOfNames: %d\r\n", ExportDirectory->NumberOfNames);

    if (ExportDirectory->NumberOfFunctions <= 0) { // TODO: check "ExportDirectory->NumberOfNames" instead?
        return;
    }
    printf(" * Exported Functions:\r\n");

    uint16_t* AddressOfNameOrdinals = (uint16_t*) RelativeVirtualAddressToRawAddress(ExportDirectory->AddressOfNameOrdinals, _DOSHeader, _FileHeader, _Image);
    uint32_t* AddressOfFunctions = (uint32_t*) RelativeVirtualAddressToRawAddress(ExportDirectory->AddressOfFunctions, _DOSHeader, _FileHeader, _Image);
    uint32_t* AddressOfNames = (uint32_t*) RelativeVirtualAddressToRawAddress(ExportDirectory->AddressOfNames, _DOSHeader, _FileHeader, _Image);
    
    for (size_t i = 0; i < (size_t)ExportDirectory->NumberOfNames; i++) {

        char* FuncAddr = (char*) RelativeVirtualAddressToRawAddress(AddressOfFunctions[i], _DOSHeader, _FileHeader, _Image);
        char* FuncName = (char*) RelativeVirtualAddressToRawAddress(AddressOfNames[i], _DOSHeader, _FileHeader, _Image);
        
        if (!FuncName || !FuncAddr) continue;

        uint32_t Ordinal = ExportDirectory->Base + AddressOfNameOrdinals[i];
        uint32_t FunctionRVA = (uint32_t) AddressOfFunctions[AddressOfNameOrdinals[i]];
        uint32_t NameRVA = (uint32_t) AddressOfNames[i];

        uint32_t ImageOffset = RelativeVirtualAddressToImageOffset(AddressOfFunctions[AddressOfNameOrdinals[i]], _DOSHeader, _FileHeader, _Image);
        
        printf("   - Ordinal=0x%x FunctionRVA=0x%x (ImageOffset=0x%x) NameRVA=0x%x FunctionName=%s\r\n", Ordinal, FunctionRVA, ImageOffset, NameRVA, FuncName);
    }
}

void PrintDataDirectory(IMAGE_DATA_DIRECTORY* DataDirectory, uint32_t NumberOfRvaAndSizes) {

    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory

    for (uint32_t i = 0; i < NumberOfRvaAndSizes; i++) {
        switch (i) {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:
            IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(RelativeVirtualAddressToRawAddress(
                DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                _DOSHeader,
                _FileHeader,
                _Image));
            PrintDataDirectoryEntryExport(ExportDirectory);
            break;
        
        default:
            continue;
        }
    }
}

// Image Optional Header: helper functions

char* VerboseSubsystem(uint16_t Subsystem) {
    switch (Subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN:
            return "Unknown";
        case IMAGE_SUBSYSTEM_NATIVE:
            return "Native";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            return "Windows CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:
            return "OS/2 CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:
            return "POSIX CUI";
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
            return "Native Windows";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
            return "Windows CE GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:
            return "EFI Application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
            return "EFI Boot Service Driver";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
            return "EFI Runtime Driver";
        case IMAGE_SUBSYSTEM_EFI_ROM:
            return "EFI ROM";
        case IMAGE_SUBSYSTEM_XBOX:
            return "XBOX";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
            return "Windows Boot Application";
        case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:
            return "XBOX Code Catalog";
        default:
            return "Unknown";
    }
}

char* VerboseDllCharacteristic(uint16_t DllCharacteristics) {
    switch (DllCharacteristics) {
        case IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:
            return "High entropy 64-bit Virtual Adress space";
        case IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
            return "Dynamic base (DLL can move)";
        case IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY:
            return "Force integrity";
        case IMAGE_DLLCHARACTERISTICS_NX_COMPAT:
            return "NX compatible";
        case IMAGE_DLLCHARACTERISTICS_NO_ISOLATION:
            return "No isolation";
        case IMAGE_DLLCHARACTERISTICS_NO_SEH:
            return "Not using SEH";
        case IMAGE_DLLCHARACTERISTICS_NO_BIND:
            return "Do not bind";
        case IMAGE_DLLCHARACTERISTICS_APPCONTAINER:
            return "Execute in an App container";
        case IMAGE_DLLCHARACTERISTICS_WDM_DRIVER:
            return "Driver uses WDM model";
        case IMAGE_DLLCHARACTERISTICS_GUARD_CF:
            return "Supports Control Flow Guard";
        case IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE:
            return "Terminal server aware";
        default:
            return "Unknown";
    }
}

void PrintDllCharacteristics(uint16_t DllCharacteristics) {
    for (int i = 0; i < 16; i++) {
        if (DllCharacteristics & (1 << i)) {
            printf("   - %s\r\n", VerboseDllCharacteristic(1 << i));
        }
    }
}

// Image Optional Header (32 and 64 bit)

void PrintOptionalHeader32(IMAGE_OPTIONAL_HEADER32* OptionalHeader) {

    printf("\r\n[+] Optional header 32-bit\r\n");

    printf(" * Magic: 0x%x\r\n", OptionalHeader->Magic);
    printf(" * Major linker version: 0x%x\r\n", OptionalHeader->MajorLinkerVersion);
    printf(" * Minor linker version: 0x%x\r\n", OptionalHeader->MinorLinkerVersion);
    printf(" * Size of code: 0x%x\r\n", OptionalHeader->SizeOfCode);
    printf(" * Size of initialized data: 0x%x\r\n", OptionalHeader->SizeOfInitializedData);
    printf(" * Size of uninitialized data: 0x%x\r\n", OptionalHeader->SizeOfUninitializedData);
    printf(" * Address of entry point: 0x%x\r\n", OptionalHeader->AddressOfEntryPoint);
    printf(" * Base of Code: 0x%x\r\n", OptionalHeader->BaseOfCode);
    printf(" * Image Base: 0x%x\r\n", OptionalHeader->ImageBase);
    printf(" * Section Alignment: 0x%x\r\n", OptionalHeader->SectionAlignment);
    printf(" * File Alignment: 0x%x\r\n", OptionalHeader->FileAlignment);
    printf(" * Major operating system version: 0x%x\r\n", OptionalHeader->MajorOperatingSystemVersion);
    printf(" * Minor operating system version: 0x%x\r\n", OptionalHeader->MinorOperatingSystemVersion);
    printf(" * Major image version: 0x%x\r\n", OptionalHeader->MajorImageVersion);
    printf(" * Minor image version: 0x%x\r\n", OptionalHeader->MinorImageVersion);
    printf(" * Major subsystem version: 0x%x\r\n", OptionalHeader->MajorSubsystemVersion);
    printf(" * Minor subsystem version: 0x%x\r\n", OptionalHeader->MinorSubsystemVersion);
    printf(" * Win32 Version Value: 0x%x\r\n", OptionalHeader->Win32VersionValue);
    printf(" * Size of image: 0x%x\r\n", OptionalHeader->SizeOfImage);
    printf(" * Size of headers: 0x%x\r\n", OptionalHeader->SizeOfHeaders);
    printf(" * Checksum: 0x%x\r\n", OptionalHeader->CheckSum);
    printf(" * Subsystem: %s\r\n", VerboseSubsystem(OptionalHeader->Subsystem));
    printf(" * DLL characteristics (0x%x):\r\n", OptionalHeader->DllCharacteristics);
    PrintDllCharacteristics(OptionalHeader->DllCharacteristics);
    printf(" * Size of stack reserve: 0x%x\r\n", OptionalHeader->SizeOfStackReserve);
    printf(" * Size of stack commit: 0x%x\r\n", OptionalHeader->SizeOfStackCommit);
    printf(" * Size of heap reserve: 0x%x\r\n", OptionalHeader->SizeOfHeapReserve);
    printf(" * Size of heap commit: 0x%x\r\n", OptionalHeader->SizeOfHeapCommit);
    printf(" * Loader flags: 0x%x\r\n", OptionalHeader->LoaderFlags); // TODO map
    printf(" * Number of RVA and sizes: 0x%x\r\n", OptionalHeader->NumberOfRvaAndSizes);

    PrintDataDirectory(OptionalHeader->DataDirectory, OptionalHeader->NumberOfRvaAndSizes);
}

void PrintOptionalHeader64(IMAGE_OPTIONAL_HEADER64* OptionalHeader) {

    printf("\r\n[+] Optional header 64-bit\r\n");

    printf(" * Magic: 0x%x\r\n", OptionalHeader->Magic);
    printf(" * Major linker version: 0x%x\r\n", OptionalHeader->MajorLinkerVersion);
    printf(" * Minor linker version: 0x%x\r\n", OptionalHeader->MinorLinkerVersion);
    printf(" * Size of code: 0x%x\r\n", OptionalHeader->SizeOfCode);
    printf(" * Size of initialized data: 0x%x\r\n", OptionalHeader->SizeOfInitializedData);
    printf(" * Size of uninitialized data: 0x%x\r\n", OptionalHeader->SizeOfUninitializedData);
    printf(" * Address of entry point: 0x%x\r\n", OptionalHeader->AddressOfEntryPoint);
    printf(" * Base of Code: 0x%x\r\n", OptionalHeader->BaseOfCode);
    printf(" * Image Base: 0x%llx\r\n", OptionalHeader->ImageBase);
    printf(" * Section Alignment: 0x%x\r\n", OptionalHeader->SectionAlignment);
    printf(" * File Alignment: 0x%x\r\n", OptionalHeader->FileAlignment);
    printf(" * Major operating system version: 0x%x\r\n", OptionalHeader->MajorOperatingSystemVersion);
    printf(" * Minor operating system version: 0x%x\r\n", OptionalHeader->MinorOperatingSystemVersion);
    printf(" * Major image version: 0x%x\r\n", OptionalHeader->MajorImageVersion);
    printf(" * Minor image version: 0x%x\r\n", OptionalHeader->MinorImageVersion);
    printf(" * Major subsystem version: 0x%x\r\n", OptionalHeader->MajorSubsystemVersion);
    printf(" * Minor subsystem version: 0x%x\r\n", OptionalHeader->MinorSubsystemVersion);
    printf(" * Win32 Version Value: 0x%x\r\n", OptionalHeader->Win32VersionValue);
    printf(" * Size of image: 0x%x\r\n", OptionalHeader->SizeOfImage);
    printf(" * Size of headers: 0x%x\r\n", OptionalHeader->SizeOfHeaders);
    printf(" * Checksum: 0x%x\r\n", OptionalHeader->CheckSum);
    printf(" * Subsystem: %s\r\n", VerboseSubsystem(OptionalHeader->Subsystem));
    printf(" * DLL characteristics (0x%x):\r\n", OptionalHeader->DllCharacteristics);
    PrintDllCharacteristics(OptionalHeader->DllCharacteristics);
    printf(" * Size of stack reserve: 0x%llx\r\n", OptionalHeader->SizeOfStackReserve);
    printf(" * Size of stack commit: 0x%llx\r\n", OptionalHeader->SizeOfStackCommit);
    printf(" * Size of heap reserve: 0x%llx\r\n", OptionalHeader->SizeOfHeapReserve);
    printf(" * Size of heap commit: 0x%llx\r\n", OptionalHeader->SizeOfHeapCommit);
    printf(" * Loader flags: 0x%x\r\n", OptionalHeader->LoaderFlags); // TODO map
    printf(" * Number of RVA and sizes: 0x%x\r\n", OptionalHeader->NumberOfRvaAndSizes);

    PrintDataDirectory(OptionalHeader->DataDirectory, OptionalHeader->NumberOfRvaAndSizes);
}

// Symbol Table

void PrintSymbols(uint32_t PointerToSymbolTable, uint32_t NumberOfSymbols) {
    // TODO
}

// File Header: helper functions

char* VerboseImageMachine(uint16_t Machine) {
    switch (Machine) {
        case IMAGE_FILE_MACHINE_UNKNOWN:
            return "Unknown";
        case IMAGE_FILE_MACHINE_TARGET_HOST:
            return "Target host (not a WoW guest)";
        case IMAGE_FILE_MACHINE_I386:
            return "Intel 386";
        case IMAGE_FILE_MACHINE_R3000:
            return "MIPS little-endian, 0x160 big-endian R3000";
        case IMAGE_FILE_MACHINE_R4000:
            return "MIPS little-endian R4000";
        case IMAGE_FILE_MACHINE_R10000:
            return "MIPS little-endian R10000";
        case IMAGE_FILE_MACHINE_WCEMIPSV2:
            return "MIPS little-endian WCE v2";
        case IMAGE_FILE_MACHINE_ALPHA:
            return "Alpha_AXP";
        case IMAGE_FILE_MACHINE_SH3:
            return "SH3 little-endian";
        case IMAGE_FILE_MACHINE_SH3DSP:
            return "SH3DSP";
        case IMAGE_FILE_MACHINE_SH3E:
            return "SH3E little-endian";
        case IMAGE_FILE_MACHINE_SH4:
            return "SH4 little-endian";
        case IMAGE_FILE_MACHINE_SH5:
            return "SH5";
        case IMAGE_FILE_MACHINE_ARM:
            return "ARM Little-Endian";
        case IMAGE_FILE_MACHINE_THUMB:
            return "ARM Thumb/Thumb-2 Little-Endian";
        case IMAGE_FILE_MACHINE_ARMNT:
            return "ARM Thumb-2 Little-Endian";
        case IMAGE_FILE_MACHINE_AM33:    
            return "AM33";
        case IMAGE_FILE_MACHINE_POWERPC:
            return "IBM PowerPC Little-Endian";
        case IMAGE_FILE_MACHINE_POWERPCFP:
            return "PowerPCFP";
        case IMAGE_FILE_MACHINE_IA64:
            return "Intel 64";
        case IMAGE_FILE_MACHINE_MIPS16:
            return "MIPS";
        case IMAGE_FILE_MACHINE_ALPHA64:
            return "ALPHA64/AXP64";
        // case IMAGE_FILE_MACHINE_AXP64:
        //     return "ALPHA64/AXP64";
        case IMAGE_FILE_MACHINE_MIPSFPU:
            return "MIPS FPU";
        case IMAGE_FILE_MACHINE_MIPSFPU16:
            return "MIPS FPU16";
        case IMAGE_FILE_MACHINE_TRICORE:
            return "Infineon";
        case IMAGE_FILE_MACHINE_CEF:
            return "CEF";
        case IMAGE_FILE_MACHINE_EBC:
            return "EFI Byte Code";
        case IMAGE_FILE_MACHINE_AMD64:
            return "AMD64 (K8)";
        case IMAGE_FILE_MACHINE_M32R:
            return "M32R little-endian";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64 Little-Endian";
        case IMAGE_FILE_MACHINE_CEE:
            return "CEE";
        default:
            return "Unknown";
    }
}

char* VerboseCharacteristic(uint16_t Characteristics) {
    switch (Characteristics) {
        case IMAGE_FILE_RELOCS_STRIPPED:
            return "Relocation information stripped (must be loaded at its preferred base address)";
        case IMAGE_FILE_EXECUTABLE_IMAGE:
            return "Executable (there are no unresolved external references)";
        case IMAGE_FILE_LINE_NUMS_STRIPPED:
            return "COFF line numbers were stripped from the file";
        case IMAGE_FILE_LOCAL_SYMS_STRIPPED:
            return "COFF symbol table entries were stripped from file";
        case IMAGE_FILE_AGGRESIVE_WS_TRIM:
            return "Aggressively trim the working set";
        case IMAGE_FILE_LARGE_ADDRESS_AWARE:
            return "The application can handle addresses larger than 2 GB";
        case IMAGE_FILE_BYTES_REVERSED_LO:
            return "The bytes of the word are reversed (LO)";
        case IMAGE_FILE_32BIT_MACHINE:
            return "32-bit machine";
        case IMAGE_FILE_DEBUG_STRIPPED:
            return "Debugging information was removed";
        case IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:
            return "If is on removable media, copy and run it from the swap file";
        case IMAGE_FILE_NET_RUN_FROM_SWAP:
            return "If is on the network, copy and run it from the swap file";
        case IMAGE_FILE_SYSTEM:
            return "The image is a system file";
        case IMAGE_FILE_DLL:
            return "The image is a DLL file";
        case IMAGE_FILE_UP_SYSTEM_ONLY:
            return "Should be run only on a uniprocessor computer";
        case IMAGE_FILE_BYTES_REVERSED_HI:
            return "The bytes of the word are reversed (HI)";
        default:
            return "Unknown";
    }
}

void PrintFileHeaderCharacteristics(uint16_t Characteristics) {
    for (int i = 0; i < 16; i++) {
        if (Characteristics & (1 << i)) {
            printf("   - %s\r\n", VerboseCharacteristic(1 << i));
        }
    }
}

// File Header

void PrintFileHeader(IMAGE_FILE_HEADER* FileHeader) {

    printf("\r\n[+] File header\r\n");

    printf(" * Machine: %s (0x%x)\r\n", VerboseImageMachine(FileHeader->Machine), FileHeader->Machine);
    printf(" * Number of sections: 0x%x\r\n", FileHeader->NumberOfSections);
    printf(" * Time date stamp: 0x%x\r\n", FileHeader->TimeDateStamp);
    printf(" * Pointer to symbol table: 0x%x\r\n", FileHeader->PointerToSymbolTable);
    printf(" * Number of symbols: 0x%x\r\n", FileHeader->NumberOfSymbols);
    printf(" * Size of optional header: 0x%x\r\n", FileHeader->SizeOfOptionalHeader);
    printf(" * Characteristics (0x%x):\r\n", FileHeader->Characteristics);
    PrintFileHeaderCharacteristics(FileHeader->Characteristics);

    // PrintSymbols(FileHeader->PointerToSymbolTable, FileHeader->NumberOfSymbols);
}

// NT Header

void PrintNTHeader(IMAGE_NT_HEADERS* NTHeader) {

    printf("\r\n[+] NT header\r\n");

    if(NTHeader->Signature != IMAGE_NT_SIGNATURE) {
        printf("[!] Error: Could not find NT signature.\r\n");
        exit(1);
    }

    printf(" * Signature: 0x%x\r\n", NTHeader->Signature);

    IMAGE_FILE_HEADER* FileHeader = (IMAGE_FILE_HEADER*) &NTHeader->FileHeader;
    _FileHeader = FileHeader;
    PrintFileHeader(FileHeader);

    if (FileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        IMAGE_OPTIONAL_HEADER32* OptionalHeader = (IMAGE_OPTIONAL_HEADER32*) &NTHeader->OptionalHeader;
        _OptionalHeader = (char*) OptionalHeader;
        PrintOptionalHeader32(OptionalHeader);
    }
    else if (FileHeader->Machine == IMAGE_FILE_MACHINE_IA64 || FileHeader->Machine == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_OPTIONAL_HEADER64* OptionalHeader = (IMAGE_OPTIONAL_HEADER64*) &NTHeader->OptionalHeader;
        _OptionalHeader = (char*) OptionalHeader;
        PrintOptionalHeader64(OptionalHeader);
    }
}

// Section Header: helper functions

char* VerboseSectionCharacteristic(uint32_t Characteristics) {

    switch (Characteristics) {
        /*case IMAGE_SCN_TYPE_DSECT:
            return "Reserved";
        case IMAGE_SCN_TYPE_NOLOAD:
            return "Do not load section into memory";
        case IMAGE_SCN_TYPE_GROUP:
            return "Section contains COMDAT data";*/
        case IMAGE_SCN_TYPE_NO_PAD:
            return "Section should not be padded to the next boundary";
        /*case IMAGE_SCN_TYPE_COPY:
            return "Section contains initialized data";*/
        case IMAGE_SCN_CNT_CODE:
            return "Section contains executable code";
        case IMAGE_SCN_CNT_INITIALIZED_DATA:
            return "Section contains initialized data";
        case IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            return "Section contains uninitialized data";
        case IMAGE_SCN_LNK_OTHER:
            return "Reserved";
        case IMAGE_SCN_LNK_INFO:
            return "Section contains comments or other information";
        /*case IMAGE_SCN_TYPE_OVER:
            return "Reserved";*/
        case IMAGE_SCN_LNK_REMOVE:
            return "Section will not become part of the image";
        case IMAGE_SCN_LNK_COMDAT:
            return "Section contains COMDAT data";
        case IMAGE_SCN_NO_DEFER_SPEC_EXC:
            return "Reset speculative exceptions handling bits in the TLB entries for this section";
        case IMAGE_SCN_GPREL:
            return "Section contains data referenced through the global pointer (GP)";
        case IMAGE_SCN_MEM_PURGEABLE:
            return "Reserved";
        /*case IMAGE_SCN_MEM_16BIT:
            return "Reserved";*/
        case IMAGE_SCN_MEM_LOCKED:
            return "Reserved";
        case IMAGE_SCN_MEM_PRELOAD:
            return "Reserved";
        case IMAGE_SCN_ALIGN_1BYTES:
            return "Align data on a 1-byte boundary";
        case IMAGE_SCN_ALIGN_2BYTES:
            return "Align data on a 2-byte boundary";
        case IMAGE_SCN_ALIGN_4BYTES:
            return "Align data on a 4-byte boundary";
        case IMAGE_SCN_ALIGN_8BYTES:
            return "Align data on an 8-byte boundary";
        case IMAGE_SCN_ALIGN_16BYTES:
            return "Align data on a 16-byte boundary";
        case IMAGE_SCN_ALIGN_32BYTES:
            return "Align data on a 32-byte boundary";
        case IMAGE_SCN_ALIGN_64BYTES:
            return "Align data on a 64-byte boundary";
        case IMAGE_SCN_ALIGN_128BYTES:
            return "Align data on a 128-byte boundary";
        case IMAGE_SCN_ALIGN_256BYTES:
            return "Align data on a 256-byte boundary";
        case IMAGE_SCN_ALIGN_512BYTES:
            return "Align data on a 512-byte boundary";
        case IMAGE_SCN_ALIGN_1024BYTES:
            return "Align data on a 1024-byte boundary";
        case IMAGE_SCN_ALIGN_2048BYTES:
            return "Align data on a 2048-byte boundary";
        case IMAGE_SCN_ALIGN_4096BYTES:
            return "Align data on a 4096-byte boundary";
        case IMAGE_SCN_ALIGN_8192BYTES:
            return "Align data on an 8192-byte boundary";
        case IMAGE_SCN_LNK_NRELOC_OVFL:
            return "Section contains extended relocations";
        case IMAGE_SCN_MEM_DISCARDABLE:
            return "Section can be discarded";
        case IMAGE_SCN_MEM_NOT_CACHED:
            return "Section cannot be cached";
        case IMAGE_SCN_MEM_NOT_PAGED:
            return "Section is not pageable";
        case IMAGE_SCN_MEM_SHARED:
            return "Section can be shared in memory";
        case IMAGE_SCN_MEM_EXECUTE:
            return "Section can be executed as code";
        case IMAGE_SCN_MEM_READ:
            return "Section can be read";
        case IMAGE_SCN_MEM_WRITE:
            return "Section can be written to";
        default:
            return "Unknown";
    }
}

void PrintSectionCharacteristics(uint32_t Characteristics) {
    for (int i = 0; i < 32; i++) {
        if (Characteristics & (1 << i)) {
            printf("     - %s\r\n", VerboseSectionCharacteristic(1 << i));
        }
    }
}

// Section Header

void PrintSectionHeader(IMAGE_SECTION_HEADER* SectionHeader) {

    printf(" * Section name: %s\r\n", SectionHeader->Name);
    printf("   - Virtual Size: 0x%x\r\n", SectionHeader->Misc.VirtualSize);
    printf("   - Virtual Address: 0x%x\r\n", SectionHeader->VirtualAddress);
    printf("   - Size of Raw Data: %d\r\n", SectionHeader->SizeOfRawData);
    printf("   - Pointer to Raw Data: 0x%x\r\n", SectionHeader->PointerToRawData);
    printf("   - Pointer to Relocations: 0x%x\r\n", SectionHeader->PointerToRelocations);
    printf("   - Pointer to Line numbers: 0x%x\r\n", SectionHeader->PointerToLinenumbers);
    printf("   - Number of Relocations: %d\r\n", SectionHeader->NumberOfRelocations);
    printf("   - Number of Line numbers: %d\r\n", SectionHeader->NumberOfLinenumbers);
    printf("   - Characteristics: 0x%x\r\n", SectionHeader->Characteristics);
    PrintSectionCharacteristics(SectionHeader->Characteristics);
}

void PrintSectionsHeaders(IMAGE_SECTION_HEADER* SectionTable, uint16_t NumberOfSections) {

    printf("\r\n[+] Sections headers\r\n");

    for (uint16_t i = 0; i < NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* SectionHeader = &SectionTable[i];
        PrintSectionHeader(SectionHeader);
    }
}

// PE

void PrintPE(char* Buffer) {

    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

    _Image = Buffer;

    // Print DOS header
    IMAGE_DOS_HEADER* DOSHeader = (IMAGE_DOS_HEADER*) Buffer;
    _DOSHeader = DOSHeader;
    PrintDOSHeader(DOSHeader);

    // Print NT header
    IMAGE_NT_HEADERS* NTHeader = (IMAGE_NT_HEADERS*) (Buffer + DOSHeader->e_lfanew);
    _NTHeader = NTHeader;
    PrintNTHeader(NTHeader);

    // Print Sections headers
    IMAGE_SECTION_HEADER* SectionTable = (IMAGE_SECTION_HEADER*)((char*) NTHeader + sizeof(IMAGE_NT_SIGNATURE) + sizeof(IMAGE_FILE_HEADER) + NTHeader->FileHeader.SizeOfOptionalHeader);
    _SectionTable = SectionTable;
    uint16_t NumberOfSections = NTHeader->FileHeader.NumberOfSections;
    PrintSectionsHeaders(SectionTable, NumberOfSections);
}

// Main

void Usage(char* argv[]) {
    printf("Usage: %s <PE_EXEC> \r\n", argv[0]);
    exit(1);
}

int main(int argc, char* argv[]) {

    // Parse arguments
    if (argc != 2)
        Usage(argv);
    
    // Header
    printf("\
 _____ _____          _         _\r\n\
|  _  |   __|  __   _| |_ _ ___| |_\r\n\
|   __|   __| |__| | . | | |  _| '_|\r\n\
|__|  |_____|      |___|___|___|_,_| " VERSION "\r\n\r\n");

    // Open and Read file
    char* Buffer = OpenReadFile(argv[1]);

    // Parse PE
    PrintPE(Buffer);

    free(Buffer);
    return 0;
}
