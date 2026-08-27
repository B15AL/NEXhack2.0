/*
===============================================================
        GENERAL WINDOWS EXE STATIC ANALYZER
        Defensive / EDR Hackathon Prototype
===============================================================

What it does:
    1. Reads a Windows EXE without executing it
    2. Validates DOS + PE headers
    3. Detects x86 / x64
    4. Lists PE sections
    5. Calculates section entropy
    6. Detects suspicious section permissions
    7. Parses imported DLLs and APIs
    8. Extracts suspicious strings
    9. Detects possible packing/obfuscation indicators
   10. Produces a heuristic malware-risk score
   11. Produces JSON-like evidence for an AI layer

What it DOES NOT do:
    - Execute the EXE
    - Detonate malware
    - Inject code
    - Bypass antivirus
    - Guarantee that a file is malware
    - Recover the original source code perfectly

Compile (MinGW):
    gcc analyzer.c -o analyzer.exe -lm

Run:
    analyzer.exe sample.exe

===============================================================
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#define MAX_STRINGS 200
#define MAX_STRING_LENGTH 512
#define MAX_APIS 500

/* ============================================================
   DATA STRUCTURES
   ============================================================ */

typedef struct
{
    char name[9];

    DWORD virtualAddress;
    DWORD virtualSize;

    DWORD rawAddress;
    DWORD rawSize;

    DWORD characteristics;

    double entropy;

    int executable;
    int writable;
    int readable;

} SectionInfo;


typedef struct
{
    int highEntropySections;
    int suspiciousSections;
    int rwxSections;

    int suspiciousAPIs;
    int suspiciousStrings;

    int possiblePacking;
    int dynamicAPIResolution;

    int overlayPresent;

    double averageEntropy;
    double maximumEntropy;

    int obfuscationScore;
    int malwareRiskScore;

} AnalysisResult;


/* ============================================================
   UTILITY
   ============================================================ */

void separator()
{
    printf("\n============================================================\n");
}


void error_exit(const char *message)
{
    printf("\n[ERROR] %s\n", message);
    exit(1);
}


/* ============================================================
   FILE LOADING
   ============================================================ */

unsigned char *load_file(
    const char *filename,
    size_t *fileSize)
{
    FILE *fp;

    fp = fopen(filename, "rb");

    if (!fp)
        error_exit("Could not open file.");

    fseek(fp, 0, SEEK_END);

    long size = ftell(fp);

    fseek(fp, 0, SEEK_SET);

    if (size <= 0)
    {
        fclose(fp);
        error_exit("Invalid file size.");
    }

    unsigned char *buffer =
        (unsigned char *)malloc(size);

    if (!buffer)
    {
        fclose(fp);
        error_exit("Memory allocation failed.");
    }

    size_t read =
        fread(buffer, 1, size, fp);

    fclose(fp);

    if (read != (size_t)size)
    {
        free(buffer);
        error_exit("Could not read complete file.");
    }

    *fileSize = (size_t)size;

    return buffer;
}


/* ============================================================
   PE VALIDATION
   ============================================================ */

IMAGE_NT_HEADERS64 *get_nt_headers(
    unsigned char *buffer,
    size_t fileSize)
{
    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        error_exit("File too small for DOS header.");

    IMAGE_DOS_HEADER *dos =
        (IMAGE_DOS_HEADER *)buffer;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        error_exit("Invalid DOS signature.");

    if (dos->e_lfanew <= 0 ||
        (size_t)dos->e_lfanew + 4 > fileSize)
        error_exit("Invalid PE offset.");

    DWORD peOffset = dos->e_lfanew;

    DWORD signature =
        *(DWORD *)(buffer + peOffset);

    if (signature != IMAGE_NT_SIGNATURE)
        error_exit("Invalid PE signature.");

    return (IMAGE_NT_HEADERS64 *)
        (buffer + peOffset);
}


/* ============================================================
   RVA -> FILE OFFSET
   ============================================================ */

DWORD rva_to_offset(
    DWORD rva,
    IMAGE_NT_HEADERS64 *nt)
{
    IMAGE_SECTION_HEADER *sections =
        IMAGE_FIRST_SECTION(nt);

    WORD numberOfSections =
        nt->FileHeader.NumberOfSections;

    for (WORD i = 0;
         i < numberOfSections;
         i++)
    {
        DWORD sectionVA =
            sections[i].VirtualAddress;

        DWORD sectionSize =
            sections[i].Misc.VirtualSize;

        if (sectionSize == 0)
            sectionSize =
                sections[i].SizeOfRawData;

        if (rva >= sectionVA &&
            rva < sectionVA + sectionSize)
        {
            return sections[i].PointerToRawData +
                   (rva - sectionVA);
        }
    }

    return 0;
}


/* ============================================================
   ENTROPY
   ============================================================ */

double calculate_entropy(
    unsigned char *data,
    size_t size)
{
    if (!data || size == 0)
        return 0.0;

    unsigned long long frequency[256];

    memset(frequency, 0, sizeof(frequency));

    for (size_t i = 0; i < size; i++)
        frequency[data[i]]++;

    double entropy = 0.0;

    for (int i = 0; i < 256; i++)
    {
        if (frequency[i] == 0)
            continue;

        double probability =
            (double)frequency[i] /
            (double)size;

        entropy -=
            probability *
            (log(probability) / log(2.0));
    }

    return entropy;
}


/* ============================================================
   SECTION ANALYSIS
   ============================================================ */

void analyze_sections(
    unsigned char *buffer,
    size_t fileSize,
    IMAGE_NT_HEADERS64 *nt,
    AnalysisResult *result)
{
    separator();

    printf("SECTION ANALYSIS\n");

    IMAGE_SECTION_HEADER *sections =
        IMAGE_FIRST_SECTION(nt);

    int count =
        nt->FileHeader.NumberOfSections;

    double entropySum = 0.0;

    int validSections = 0;

    for (int i = 0; i < count; i++)
    {
        SectionInfo info;

        memset(&info, 0, sizeof(info));

        memcpy(
            info.name,
            sections[i].Name,
            8);

        info.virtualAddress =
            sections[i].VirtualAddress;

        info.virtualSize =
            sections[i].Misc.VirtualSize;

        info.rawAddress =
            sections[i].PointerToRawData;

        info.rawSize =
            sections[i].SizeOfRawData;

        info.characteristics =
            sections[i].Characteristics;

        info.executable =
            (info.characteristics &
             IMAGE_SCN_MEM_EXECUTE) != 0;

        info.writable =
            (info.characteristics &
             IMAGE_SCN_MEM_WRITE) != 0;

        info.readable =
            (info.characteristics &
             IMAGE_SCN_MEM_READ) != 0;

        if (info.rawSize > 0 &&
            info.rawAddress < fileSize &&
            info.rawSize <=
                fileSize - info.rawAddress)
        {
            info.entropy =
                calculate_entropy(
                    buffer + info.rawAddress,
                    info.rawSize);

            entropySum += info.entropy;

            validSections++;
        }

        printf("\n[%d] %s\n", i + 1, info.name);

        printf("    Virtual Size : %lu\n",
               (unsigned long)info.virtualSize);

        printf("    Raw Size     : %lu\n",
               (unsigned long)info.rawSize);

        printf("    Entropy      : %.3f\n",
               info.entropy);

        printf("    Read         : %s\n",
               info.readable ? "YES" : "NO");

        printf("    Write        : %s\n",
               info.writable ? "YES" : "NO");

        printf("    Execute      : %s\n",
               info.executable ? "YES" : "NO");


        /*
           High entropy does NOT mean malware.

           It can indicate:
             - compression
             - encryption
             - packing
             - random data
        */

        if (info.entropy >= 7.0)
        {
            printf("    [!] HIGH ENTROPY\n");

            result->highEntropySections++;
        }


        /*
           RWX section:
               Read + Write + Execute

           This can be suspicious, although legitimate
           software can occasionally have unusual permissions.
        */

        if (info.executable &&
            info.writable)
        {
            printf("    [!] EXECUTABLE + WRITABLE\n");

            result->rwxSections++;
            result->suspiciousSections++;
        }


        /*
           Suspicious/nonstandard section names
        */

        if (strcmp(info.name, ".text") != 0 &&
            strcmp(info.name, ".data") != 0 &&
            strcmp(info.name, ".rdata") != 0 &&
            strcmp(info.name, ".rsrc") != 0 &&
            strcmp(info.name, ".reloc") != 0 &&
            strcmp(info.name, ".pdata") != 0 &&
            strcmp(info.name, ".idata") != 0 &&
            strcmp(info.name, ".edata") != 0)
        {
            printf("    [!] NON-STANDARD SECTION NAME\n");

            result->suspiciousSections++;
        }
    }

    if (validSections > 0)
    {
        result->averageEntropy =
            entropySum / validSections;
    }
}


/* ============================================================
   STRING ANALYSIS
   ============================================================ */

int is_printable(unsigned char c)
{
    return c >= 32 && c <= 126;
}


int suspicious_string(
    const char *str)
{
    const char *patterns[] =
    {
        "http://",
        "https://",
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "AppData",
        "Startup",
        "CurrentVersion",
        "RunOnce",
        "password",
        "passwd",
        "token",
        "cookie",
        "download",
        "execute",
        "CreateProcess",
        "VirtualAlloc",
        "WriteProcessMemory"
    };

    int count =
        sizeof(patterns) /
        sizeof(patterns[0]);

    for (int i = 0; i < count; i++)
    {
        if (strstr(str, patterns[i]) != NULL)
            return 1;
    }

    return 0;
}


void scan_ascii_strings(
    unsigned char *buffer,
    size_t fileSize,
    AnalysisResult *result)
{
    separator();

    printf("STRING ANALYSIS\n");

    char current[MAX_STRING_LENGTH];

    size_t position = 0;

    int printed = 0;

    for (size_t i = 0;
         i < fileSize;
         i++)
    {
        unsigned char c =
            buffer[i];

        if (is_printable(c))
        {
            if (position <
                MAX_STRING_LENGTH - 1)
            {
                current[position++] =
                    (char)c;
            }
        }
        else
        {
            if (position >= 6)
            {
                current[position] =
                    '\0';

                if (suspicious_string(current))
                {
                    printf("\n    %s",
                           current);

                    result->suspiciousStrings++;

                    printed++;

                    if (printed >=
                        MAX_STRINGS)
                        break;
                }
            }

            position = 0;
        }
    }
}


/* ============================================================
   IMPORT ANALYSIS
   ============================================================ */

int suspicious_api(
    const char *api)
{
    const char *apis[] =
    {
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",

        "WriteProcessMemory",
        "ReadProcessMemory",

        "CreateRemoteThread",

        "OpenProcess",

        "LoadLibraryA",
        "LoadLibraryW",

        "GetProcAddress",

        "CreateProcessA",
        "CreateProcessW",

        "WinExec",

        "ShellExecuteA",
        "ShellExecuteW",

        "URLDownloadToFileA",
        "URLDownloadToFileW",

        "InternetOpenA",
        "InternetOpenW",

        "InternetConnectA",
        "InternetConnectW",

        "RegCreateKeyA",
        "RegCreateKeyW",

        "RegSetValueA",
        "RegSetValueW",

        "OpenSCManagerA",
        "OpenSCManagerW",

        "CreateServiceA",
        "CreateServiceW"
    };

    int count =
        sizeof(apis) /
        sizeof(apis[0]);

    for (int i = 0;
         i < count;
         i++)
    {
        if (_stricmp(
                api,
                apis[i]) == 0)
            return 1;
    }

    return 0;
}


void analyze_imports(
    unsigned char *buffer,
    size_t fileSize,
    IMAGE_NT_HEADERS64 *nt,
    AnalysisResult *result)
{
    separator();

    printf("IMPORT ANALYSIS\n");

    IMAGE_DATA_DIRECTORY directory =
        nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (directory.VirtualAddress == 0)
    {
        printf("[!] Import table absent.\n");

        /*
           This can occur because of:
             - unusual binaries
             - custom loaders
             - packing
             - manually constructed PE files

           It is NOT automatically malicious.
        */

        result->possiblePacking = 1;

        return;
    }


    DWORD importOffset =
        rva_to_offset(
            directory.VirtualAddress,
            nt);

    if (importOffset == 0 ||
        importOffset >= fileSize)
    {
        printf("[!] Could not locate imports safely.\n");
        return;
    }


    IMAGE_IMPORT_DESCRIPTOR *imports =
        (IMAGE_IMPORT_DESCRIPTOR *)
        (buffer + importOffset);


    int dllCount = 0;


    for (int i = 0;
         i < 1000;
         i++)
    {
        IMAGE_IMPORT_DESCRIPTOR *desc =
            &imports[i];

        if (desc->Name == 0)
            break;

        DWORD nameOffset =
            rva_to_offset(
                desc->Name,
                nt);

        if (nameOffset == 0 ||
            nameOffset >= fileSize)
            continue;

        char *dll =
            (char *)(buffer + nameOffset);

        printf("\nDLL: %s\n", dll);

        dllCount++;


        /*
           FirstThunk / OriginalFirstThunk
           contains the imported functions.

           This implementation demonstrates the
           architecture while keeping bounds checks.
        */

        DWORD thunkRVA =
            desc->OriginalFirstThunk;

        if (thunkRVA == 0)
            thunkRVA =
                desc->FirstThunk;

        DWORD thunkOffset =
            rva_to_offset(
                thunkRVA,
                nt);

        if (thunkOffset == 0 ||
            thunkOffset >= fileSize)
            continue;


        if (nt->OptionalHeader.Magic ==
            IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_THUNK_DATA64 *thunks =
                (IMAGE_THUNK_DATA64 *)
                (buffer + thunkOffset);

            for (int j = 0;
                 j < MAX_APIS;
                 j++)
            {
                ULONGLONG value =
                    thunks[j].u1.AddressOfData;

                if (value == 0)
                    break;

                /*
                   Ordinal imports do not contain
                   a readable API name.
                */

                if (IMAGE_SNAP_BY_ORDINAL64(value))
                    continue;

                DWORD nameRVA =
                    (DWORD)value;

                DWORD nameOffset =
                    rva_to_offset(
                        nameRVA,
                        nt);

                if (nameOffset == 0 ||
                    nameOffset + 2 >= fileSize)
                    continue;

                IMAGE_IMPORT_BY_NAME *importName =
                    (IMAGE_IMPORT_BY_NAME *)
                    (buffer + nameOffset);

                char *api =
                    (char *)importName->Name;

                if (api == NULL)
                    continue;

                printf("    %s", api);

                if (suspicious_api(api))
                {
                    printf("  <-- suspicious capability");

                    result->suspiciousAPIs++;

                    if (_stricmp(
                            api,
                            "LoadLibraryA") == 0 ||
                        _stricmp(
                            api,
                            "LoadLibraryW") == 0 ||
                        _stricmp(
                            api,
                            "GetProcAddress") == 0)
                    {
                        result->dynamicAPIResolution = 1;
                    }
                }

                printf("\n");
            }
        }
        else
        {
            IMAGE_THUNK_DATA32 *thunks =
                (IMAGE_THUNK_DATA32 *)
                (buffer + thunkOffset);

            for (int j = 0;
                 j < MAX_APIS;
                 j++)
            {
                DWORD value =
                    thunks[j].u1.AddressOfData;

                if (value == 0)
                    break;

                if (IMAGE_SNAP_BY_ORDINAL32(value))
                    continue;

                DWORD nameOffset =
                    rva_to_offset(
                        value,
                        nt);

                if (nameOffset == 0 ||
                    nameOffset + 2 >= fileSize)
                    continue;

                IMAGE_IMPORT_BY_NAME *importName =
                    (IMAGE_IMPORT_BY_NAME *)
                    (buffer + nameOffset);

                char *api =
                    (char *)importName->Name;

                if (api == NULL)
                    continue;

                printf("    %s", api);

                if (suspicious_api(api))
                {
                    printf("  <-- suspicious capability");

                    result->suspiciousAPIs++;
                }

                printf("\n");
            }
        }
    }

    printf("\nImported DLLs: %d\n",
           dllCount);
}


/* ============================================================
   OVERLAY DETECTION
   ============================================================ */

void detect_overlay(
    unsigned char *buffer,
    size_t fileSize,
    IMAGE_NT_HEADERS64 *nt,
    AnalysisResult *result)
{
    IMAGE_SECTION_HEADER *sections =
        IMAGE_FIRST_SECTION(nt);

    DWORD lastEnd = 0;

    for (int i = 0;
         i < nt->FileHeader.NumberOfSections;
         i++)
    {
        DWORD end =
            sections[i].PointerToRawData +
            sections[i].SizeOfRawData;

        if (end > lastEnd)
            lastEnd = end;
    }

    if (lastEnd < fileSize)
    {
        size_t overlay =
            fileSize - lastEnd;

        printf("\n[!] Overlay detected: %zu bytes\n",
               overlay);

        result->overlayPresent = 1;
    }
}


/* ============================================================
   HEADER INFORMATION
   ============================================================ */

void print_headers(
    IMAGE_NT_HEADERS64 *nt)
{
    separator();

    printf("PE INFORMATION\n");

    printf("Machine: 0x%X\n",
           nt->FileHeader.Machine);

    if (nt->FileHeader.Machine ==
        IMAGE_FILE_MACHINE_AMD64)
    {
        printf("Architecture: x64\n");
    }
    else if (
        nt->FileHeader.Machine ==
        IMAGE_FILE_MACHINE_I386)
    {
        printf("Architecture: x86\n");
    }
    else
    {
        printf("Architecture: Other\n");
    }


    printf("Sections: %u\n",
           nt->FileHeader.NumberOfSections);

    printf("Entry Point: 0x%08lX\n",
           (unsigned long)
           nt->OptionalHeader.AddressOfEntryPoint);

    printf("Image Base: 0x%llX\n",
           (unsigned long long)
           nt->OptionalHeader.ImageBase);

    printf("Subsystem: %u\n",
           nt->OptionalHeader.Subsystem);
}


/* ============================================================
   SCORING
   ============================================================ */

void calculate_scores(
    AnalysisResult *r)
{
    int obfuscation = 0;

    int malware = 0;


    /*
       ----------------------------
       OBFUSCATION SCORE
       ----------------------------
    */

    if (r->highEntropySections > 0)
        obfuscation += 25;

    if (r->possiblePacking)
        obfuscation += 30;

    if (r->dynamicAPIResolution)
        obfuscation += 20;

    if (r->suspiciousSections >= 2)
        obfuscation += 15;

    if (r->averageEntropy >= 6.5)
        obfuscation += 10;

    if (obfuscation > 100)
        obfuscation = 100;


    /*
       ----------------------------
       MALWARE RISK
       ----------------------------

       IMPORTANT:

       This is a heuristic risk score.
       It is NOT a calibrated probability.
    */

    if (r->highEntropySections > 0)
        malware += 10;

    if (r->possiblePacking)
        malware += 10;

    if (r->rwxSections > 0)
        malware += 15;

    if (r->suspiciousAPIs >= 5)
        malware += 30;
    else if (r->suspiciousAPIs >= 2)
        malware += 20;
    else if (r->suspiciousAPIs > 0)
        malware += 10;

    if (r->suspiciousStrings > 0)
        malware += 10;

    if (r->dynamicAPIResolution)
        malware += 10;

    if (malware > 100)
        malware = 100;


    r->obfuscationScore =
        obfuscation;

    r->malwareRiskScore =
        malware;
}


/* ============================================================
   AI-READY REPORT
   ============================================================ */

void print_ai_report(
    AnalysisResult *r)
{
    separator();

    printf("AI-READY EVIDENCE\n");

    separator();

    printf("{\n");

    printf("  \"average_entropy\": %.3f,\n",
           r->averageEntropy);

    printf("  \"maximum_entropy\": %.3f,\n",
           r->maximumEntropy);

    printf("  \"high_entropy_sections\": %d,\n",
           r->highEntropySections);

    printf("  \"suspicious_sections\": %d,\n",
           r->suspiciousSections);

    printf("  \"rwx_sections\": %d,\n",
           r->rwxSections);

    printf("  \"suspicious_apis\": %d,\n",
           r->suspiciousAPIs);

    printf("  \"suspicious_strings\": %d,\n",
           r->suspiciousStrings);

    printf("  \"possible_packing\": %s,\n",
           r->possiblePacking
               ? "true"
               : "false");

    printf("  \"dynamic_api_resolution\": %s,\n",
           r->dynamicAPIResolution
               ? "true"
               : "false");

    printf("  \"overlay_present\": %s,\n",
           r->overlayPresent
               ? "true"
               : "false");

    printf("  \"obfuscation_score\": %d,\n",
           r->obfuscationScore);

    printf("  \"malware_risk_score\": %d\n",
           r->malwareRiskScore);

    printf("}\n");
}


/* ============================================================
   FINAL REPORT
   ============================================================ */

void final_report(
    AnalysisResult *r)
{
    separator();

    printf("FINAL ANALYSIS\n");

    separator();

    printf("\nObfuscation Score : %d / 100\n",
           r->obfuscationScore);

    printf("Malware Risk      : %d / 100\n",
           r->malwareRiskScore);


    printf("\nInterpretation:\n");

    if (r->malwareRiskScore < 25)
    {
        printf("LOW RISK\n");
    }
    else if (r->malwareRiskScore < 50)
    {
        printf("MEDIUM-LOW RISK\n");
    }
    else if (r->malwareRiskScore < 75)
    {
        printf("MEDIUM-HIGH RISK\n");
    }
    else
    {
        printf("HIGH RISK\n");
    }


    printf("\nImportant:\n");

    printf("This score is a heuristic assessment.\n");

    printf("It is NOT a probability that the file is malware.\n");

    printf("High entropy alone does NOT indicate malware.\n");

    printf("Static analysis cannot guarantee runtime behavior.\n");
}


/* ============================================================
   MAIN
   ============================================================ */

int main(
    int argc,
    char *argv[])
{
    if (argc != 2)
    {
        printf("\nUsage:\n");
        printf("    analyzer.exe <file.exe>\n\n");

        return 1;
    }


    const char *filename =
        argv[1];

    printf("\n");
    printf("============================================================\n");
    printf("        AI-ASSISTED EDR STATIC EXE ANALYZER\n");
    printf("============================================================\n");

    printf("\nTarget: %s\n",
           filename);


    /*
       Load EXE as raw bytes.

       Nothing is executed.
    */

    size_t fileSize;

    unsigned char *buffer =
        load_file(
            filename,
            &fileSize);

    printf("File size: %zu bytes\n",
           fileSize);


    /*
       PE validation
    */

    IMAGE_NT_HEADERS64 *nt =
        get_nt_headers(
            buffer,
            fileSize);

    printf("\n[+] Valid Windows PE detected.");


    /*
       Analysis result
    */

    AnalysisResult result;

    memset(
        &result,
        0,
        sizeof(result));


    /*
       Header information
    */

    print_headers(nt);


    /*
       Section analysis
    */

    analyze_sections(
        buffer,
        fileSize,
        nt,
        &result);


    /*
       Import analysis
    */

    analyze_imports(
        buffer,
        fileSize,
        nt,
        &result);


    /*
       Strings
    */

    scan_ascii_strings(
        buffer,
        fileSize,
        &result);


    /*
       Overlay
    */

    detect_overlay(
        buffer,
        fileSize,
        nt,
        &result);


    /*
       Find maximum entropy.

       In this simplified implementation,
       section entropy is already calculated
       during section analysis.
    */

    IMAGE_SECTION_HEADER *sections =
        IMAGE_FIRST_SECTION(nt);

    for (int i = 0;
         i < nt->FileHeader.NumberOfSections;
         i++)
    {
        DWORD raw =
            sections[i].PointerToRawData;

        DWORD size =
            sections[i].SizeOfRawData;

        if (size > 0 &&
            raw < fileSize &&
            size <= fileSize - raw)
        {
            double e =
                calculate_entropy(
                    buffer + raw,
                    size);

            if (e >
                result.maximumEntropy)
            {
                result.maximumEntropy = e;
            }
        }
    }


    /*
       Score
    */

    calculate_scores(
        &result);


    /*
       AI report
    */

    print_ai_report(
        &result);


    /*
       Final human report
    */

    final_report(
        &result);


    /*
       Cleanup
    */

    free(buffer);


    printf("\nAnalysis completed.\n");

    return 0;
}