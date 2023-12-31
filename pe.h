#ifndef _PE_
#define _PE_

/* Already included in WinNT.h by Windows.h */
#ifndef _WINNT_

// Represents the DOS header format.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// Represents the COFF header format.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header

typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;              // IMAGE_FILE_MACHINE_xxx
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;      // IMAGE_FILE_xxx
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// IMAGE_FILE_MACHINE_xxx

#define IMAGE_FILE_MACHINE_UNKNOWN           (0)
#define IMAGE_FILE_MACHINE_TARGET_HOST       (0x0001) // Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_I386              (0x014c) // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             (0x0162) // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             (0x0166) // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            (0x0168) // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         (0x0169) // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             (0x0184) // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               (0x01a2) // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            (0x01a3)
#define IMAGE_FILE_MACHINE_SH3E              (0x01a4) // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               (0x01a6) // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               (0x01a8) // SH5
#define IMAGE_FILE_MACHINE_ARM               (0x01c0) // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             (0x01c2) // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT             (0x01c4) // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33              (0x01d3)
#define IMAGE_FILE_MACHINE_POWERPC           (0x01F0) // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         (0x01f1)
#define IMAGE_FILE_MACHINE_IA64              (0x0200) // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            (0x0266) // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           (0x0284) // ALPHA64
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           (0x0366) // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         (0x0466) // MIPS
#define IMAGE_FILE_MACHINE_TRICORE           (0x0520) // Infineon
#define IMAGE_FILE_MACHINE_CEF               (0x0CEF)
#define IMAGE_FILE_MACHINE_EBC               (0x0EBC) // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             (0x8664) // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              (0x9041) // M32R little-endian
#define IMAGE_FILE_MACHINE_ARM64             (0xAA64) // ARM64 Little-Endian
#define IMAGE_FILE_MACHINE_CEE               (0xC0EE)

// IMAGE_FILE_xxx

#define IMAGE_FILE_RELOCS_STRIPPED         (0x0001) // Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.
#define IMAGE_FILE_EXECUTABLE_IMAGE        (0x0002) // The file is executable (there are no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED      (0x0004) // COFF line numbers were stripped from the file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED     (0x0008) // COFF symbol table entries were stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM       (0x0010) // Aggressively trim the working set. This value is obsolete.
#define IMAGE_FILE_LARGE_ADDRESS_AWARE     (0x0020) // The application can handle addresses larger than 2 GB.
#define IMAGE_FILE_BYTES_REVERSED_LO       (0x0080) // The bytes of the word are reversed. This flag is obsolete.
#define IMAGE_FILE_32BIT_MACHINE           (0x0100) // The computer supports 32-bit words.
#define IMAGE_FILE_DEBUG_STRIPPED          (0x0200) // Debugging information was removed and stored separately in another file.
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP (0x0400) // If the image is on removable media, copy it to and run it from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP       (0x0800) // If the image is on the network, copy it to and run it from the swap file.
#define IMAGE_FILE_SYSTEM                  (0x1000) // The image is a system file.
#define IMAGE_FILE_DLL                     (0x2000) // The image is a DLL file. While it is an executable file, it cannot be run directly.
#define IMAGE_FILE_UP_SYSTEM_ONLY          (0x4000) // The file should be run only on a uniprocessor computer.
#define IMAGE_FILE_BYTES_REVERSED_HI       (0x8000) // The bytes of the word are reversed. This flag is obsolete.

// Represents the optional header format.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                 Magic;                     // IMAGE_xxx_MAGIC
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    DWORD                BaseOfData;
    DWORD                ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;                 // IMAGE_SUBSYSTEM_xxx
    WORD                 DllCharacteristics;
    DWORD                SizeOfStackReserve;
    DWORD                SizeOfStackCommit;
    DWORD                SizeOfHeapReserve;
    DWORD                SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

// The actual structure in WinNT.h is named IMAGE_OPTIONAL_HEADER32 and IMAGE_OPTIONAL_HEADER is defined as IMAGE_OPTIONAL_HEADER32.
// However, if _WIN64 is defined, then IMAGE_OPTIONAL_HEADER is defined as IMAGE_OPTIONAL_HEADER64.

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                 Magic;                     // IMAGE_xxx_MAGIC
    BYTE                 MajorLinkerVersion;
    BYTE                 MinorLinkerVersion;
    DWORD                SizeOfCode;
    DWORD                SizeOfInitializedData;
    DWORD                SizeOfUninitializedData;
    DWORD                AddressOfEntryPoint;
    DWORD                BaseOfCode;
    ULONGLONG            ImageBase;
    DWORD                SectionAlignment;
    DWORD                FileAlignment;
    WORD                 MajorOperatingSystemVersion;
    WORD                 MinorOperatingSystemVersion;
    WORD                 MajorImageVersion;
    WORD                 MinorImageVersion;
    WORD                 MajorSubsystemVersion;
    WORD                 MinorSubsystemVersion;
    DWORD                Win32VersionValue;
    DWORD                SizeOfImage;
    DWORD                SizeOfHeaders;
    DWORD                CheckSum;
    WORD                 Subsystem;                 // IMAGE_SUBSYSTEM_xxx
    WORD                 DllCharacteristics;        // IMAGE_DLLCHARACTERISTICS_xxx
    ULONGLONG            SizeOfStackReserve;
    ULONGLONG            SizeOfStackCommit;
    ULONGLONG            SizeOfHeapReserve;
    ULONGLONG            SizeOfHeapCommit;
    DWORD                LoaderFlags;
    DWORD                NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

// IMAGE_xxx_MAGIC
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC (0x10b) // The file is an executable image (a 32-bit application).
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC (0x20b) // The file is an executable image (a 64-bit application).
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC  (0x107) // The file is a ROM image.

// IMAGE_SUBSYSTEM_xxx
#define IMAGE_SUBSYSTEM_UNKNOWN                  (0)  // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE                   (1)  // No subsystem required (device drivers and native system processes).
#define IMAGE_SUBSYSTEM_WINDOWS_GUI              (2)  // Windows graphical user interface (GUI) subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI              (3)  // Windows character-mode user interface (CUI) subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI                  (5)  // OS/2 CUI subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI                (7)  // POSIX CUI subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS           (8)  // Native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           (9)  // Windows CE system.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION          (10) // Extensible Firmware Interface (EFI) application.
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  (11) // EFI driver with boot services.
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       (12) // EFI driver with run-time services.
#define IMAGE_SUBSYSTEM_EFI_ROM                  (13) // EFI ROM image.
#define IMAGE_SUBSYSTEM_XBOX                     (14) // Xbox system.
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION (16) // Boot application.
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG        (17) // Xbox code catalog.

// IMAGE_DLLCHARACTERISTICS_xxx
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       (0x0020) // Image can handle a high entropy 64-bit virtual address space.
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          (0x0040) // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       (0x0080) // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT             (0x0100) // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          (0x0200) // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH                (0x0400) // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND               (0x0800) // Do not bind this image.
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER          (0x1000) // Image should execute in an AppContainer
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            (0x2000) // Driver uses WDM model
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF              (0x4000) // Image supports Control Flow Guard.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (0x8000)

// Represents the PE header format.
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32

typedef struct _IMAGE_NT_HEADERS {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

// The actual structure in WinNT.h is named IMAGE_NT_HEADERS32 and IMAGE_NT_HEADERS is defined as IMAGE_NT_HEADERS32.
// However, if _WIN64 is defined, then IMAGE_NT_HEADERS is defined as IMAGE_NT_HEADERS64.

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

#endif // _WINNT_

#endif // _PE_
