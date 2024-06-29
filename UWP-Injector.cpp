#pragma warning (disable: 4703)
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <ShObjIdl_core.h>
#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>
#include <psapi.h>
#include <intrin.h>

inline void printHelp(char** const& argv) {
    char* fileName = argv[0] + 3;
    for (int i = 0; fileName[i];) {
        if (fileName[i] == '\\') {
            fileName += i + 1;
            i = 0;
        }
        else {
            ++i;
        }
    }
    printf(
        "Usage: %s [OPTIONS] [FILE]\n"
        "Launch the UWP application with data injection in .text segment according to the rules specified in FILE.\n"
        "\n"
        "OPTIONS:\n"
        "    -h, --help  Display this help information and exit\n"
        , fileName
    );
}

char errorMessageFormat[] = "%s: ERROR: %s: %s\n";
const char text2hex[] = {
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  16, 16, 16, 16, 16, 17
};

int main(int argc, char** argv) {
    if (!--argc) {
        printHelp(argv);
        return 0;
    }
    struct {
        char* addr;
        enum { none, ud, nf, sf, ne } reason = none;
    } argError;
    int ruleFile = -1;
    int argI = 1;
    char* ruleFileName;
    do {
        if (argv[argI][0] == '-') {
            if (argv[argI][1] == '-') {
                if (strcmp(argv[argI] + 2, "help")) {
                    if (argError.reason == argError.none) {
                        argError = { (char*)(argv[argI][0]), argError.ud };
                    }
                }
                else {
                    printHelp(argv);
                    return 0;
                }
            }
            else {
                char* i = argv[argI] + 1;
                if (i[0] == 'h') {
                    printHelp(argv);
                    return 0;
                }
                argError = { i, argError.ud };
                ((char*)errorMessageFormat)[12] = 'c';
                while ((++i)[0]) {
                    if (i[0] == 'h') {
                        printHelp(argv);
                        return 0;
                    }
                }
            }
        }
        else if (argError.reason == argError.none) {
            if (ruleFile != -1) {
                argError = { argv[argI], argError.sf };
            }
            else {
                ruleFileName = argv[argI];
                ruleFile = _sopen(argv[argI], _O_BINARY | _O_RDONLY, _SH_DENYWR);
                if (ruleFile == -1) {
                    argError = { argv[argI], argError.nf };
                }
            }
        }
    } while (++argI <= argc);
    if (argError.reason == argError.none && !ruleFile) {
        argError.reason = argError.ne;
    }
    if (argError.reason != argError.none) {
        char* fileName = argv[0] + 3;
        for (int i = 0; fileName[i];) {
            if (fileName[i] == '\\') {
                fileName += i + 1;
                i = 0;
            }
            else {
                ++i;
            }
        }
        const char* reason;
        switch (argError.reason) {
        case argError.nf:
            reason = "File not found";
            break;
        case argError.sf:
            reason = "It is not allowed to specify multiple files";
            break;
        case argError.ne:
            reason = "No input file";
            break;
        default:
            reason = "No such option";
        }
        printf(errorMessageFormat, fileName, argError.addr, reason);
        if (ruleFile != -1) {
            _close(ruleFile);
        }
        return 1;
    }
    CoInitialize(0);
    IApplicationActivationManager* ppv;
    CoCreateInstance(CLSID_ApplicationActivationManager, 0, CLSCTX_INPROC_SERVER, IID_IApplicationActivationManager, (LPVOID*)&ppv);
    struct _stat ruleFileStat;
    _fstat((int)ruleFile, &ruleFileStat);
    char* ruleBuf = new char[ruleFileStat.st_size << 2];
    wchar_t* publicBuf = (wchar_t*)(ruleBuf + ruleFileStat.st_size);
    _read(ruleFile, ruleBuf, ruleFileStat.st_size);
    _close(ruleFile);
    char* src = ruleBuf;
    wchar_t* dst = publicBuf;
    int line = 1;
    do {
        char a = src++[0];
        if (a < 0x20) {
            --ruleFileStat.st_size;
            if (a == 10) {
                ++line;
            }
            break;
        }
        dst++[0] = a;
    } while (--ruleFileStat.st_size);
    dst[0] = 0;
    DWORD PID;
    if (ppv->ActivateApplication((LPCWSTR)publicBuf, 0, AO_NONE, &PID)) {
        src[0] = 0;
        printf("%s: Line 1: ERROR: %s: Cannot open application\n", ruleFileName, ruleBuf);
        return 1;
    }
    HANDLE PH = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
    size_t* PM;
    DWORD cbNeeded;
    K32EnumProcessModules(PH, (HMODULE*)&PM, 8, &cbNeeded);
    PM = (size_t*)new char[cbNeeded];
    K32EnumProcessModules(PH, (HMODULE*)PM, cbNeeded, &cbNeeded);
    do {
        char a = src++[0];
        if (a < 0x20) {
            if (a == 10) {
                ++line;
            }
        }
        else {
            dst++[0] = a;
            break;
        }
    } while (--ruleFileStat.st_size);
    char* moduleNameA = src - 1;
    wchar_t* moduleName = dst - 1;
    do {
        char a = src++[0];
        if (a < 0x20) {
            --ruleFileStat.st_size;
            if (a == 10) {
                ++line;
            }
            dst++[0] = 0;
            break;
        }
        dst++[0] = a;
    } while (--ruleFileStat.st_size);
    src[-1] = 0;
    size_t* PDump = (size_t*)new wchar_t[580];
    do {
        GetModuleFileNameEx(PH, (HMODULE&)(((char*)PM)[cbNeeded -= 8]), (LPWSTR)PDump, 580);
        if (!lstrcmpW((LPCWSTR)PDump, moduleName)) {
            goto FOUND;
        }
    } while (cbNeeded);
    printf("%s: Line 2: ERROR: %s: Module not found\n", ruleFileName, moduleNameA);
    return 1;
FOUND:
    PM = (size_t*&)(((char*)PM)[cbNeeded]);
    MEMORY_BASIC_INFORMATION PMBI;
    VirtualQueryEx(PH, (LPCVOID)((size_t)PM | 0x1000), &PMBI, sizeof(MEMORY_BASIC_INFORMATION));
    PDump = (size_t*)VirtualAlloc(0, PMBI.RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    size_t NumberOfBytesReaded;
    ReadProcessMemory(PH, PMBI.BaseAddress, PDump, PMBI.RegionSize, &NumberOfBytesReaded);
    if (!--ruleFileStat.st_size) {
        printf("%s: WARNING: Replace rules not found\n", ruleFileName);
        return 0;
    }
    do {
        unsigned char a = src++[0];
        if (a > ' ') {
            char* command = src - 1;
            while (true) {
                if (!--ruleFileStat.st_size) {
                    src[0] = 0;
                    printf(strcmp(command, "replace") ? "%s: Line %d: ERROR: Unknown rule %s\n" : "%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line, command);
                    return 1;
                }
                if ((a = src++[0]) > ' ') {
                    src[-1] |= 0x20;
                }
                else if (a < ' ') {
                    src[-1] = 0;
                    printf(strcmp(command, "replace") ? "%s: Line %d: ERROR: Unknown rule %s\n" : "%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line, command);
                    return 1;
                }
                else {
                    src[-1] = 0;
                    break;
                }
            }
            if (strcmp(command, "replace")) {
                printf("%s: Line %d: ERROR: Unknown rule %s\n", ruleFileName, line, command);
                return 1;
            }
            char* arg1 = (char*)publicBuf, * arg2;
            char* arg1mask = ruleBuf + (ruleFileStat.st_size << 1);
            char* arg2mask;
            int arg1size = 0;
            int arg2size = 0;
            arg1mask[0] = 0xFF;
            while (true) {
                if (!--ruleFileStat.st_size) {
                    printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                    return 1;
                }
                if ((a = src++[0]) <= ' ') {
                    if (a == 10) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                }
                else {
                    a &= 0xDF;
                    if (a & 0xC0) {
                        if (a == 'W') {
                            break;
                        }
                        if (a > 'F') {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        a ^= 0x40;
                    }
                    a = text2hex[a];
                    if (a > 16) {
                        arg1mask[arg1size] &= 0x0F;
                    }
                    else if (a == 16) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                    else {
                        arg1[arg1size] = a << 4;
                    }
                    if (!--ruleFileStat.st_size) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                    if ((a = src++[0]) <= ' ') {
                        if (a == 10) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                    }
                    else {
                        a &= 0xDF;
                        if (a & 0xC0) {
                            if (a > 'F') {
                                printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                                return 1;
                            }
                            a ^= 0x40;
                        }
                        a = text2hex[a];
                        if (a > 16) {
                            arg1mask[arg1size] &= 0xF0;
                        }
                        else if (a == 16) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        else {
                            arg1[arg1size] |= a;
                        }
                        if (!ruleFileStat.st_size) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        arg1mask[++arg1size] = 0xFF;
                    }
                }
            }
            if (!arg1size) {
                printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                return 1;
            }
            if (arg1size & 7) {
                memset(arg1mask + arg1size, 0, 8 - (arg1size & 7));
                arg1size += 8 - (arg1size & 7);
            }
            arg2 = src - 1;
            arg2mask = arg1mask + arg1size;
            arg2mask[0] = 0xFF;
            while (--ruleFileStat.st_size) {
                if ((a = src++[0]) <= ' ') {
                    if (a == 10) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                    src[-1] = 0;
                    break;
                }
            }
            if (strcmp(arg2, "with")) {
                printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                return 1;
            }
            arg2 = arg1 + arg1size;
            while (true) {
                if (!--ruleFileStat.st_size) {
                    break;
                }
                if ((a = src++[0]) <= ' ') {
                    if (a == 10) {
                        break;
                    }
                }
                else {
                    a &= 0xDF;
                    if (a & 0xC0) {
                        if (a > 'F') {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        a ^= 0x40;
                    }
                    a = text2hex[a];
                    if (a > 16) {
                        arg2mask[arg2size] &= 0x0F;
                    }
                    else if (a == 16) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                    else {
                        arg2[arg2size] = a << 4;
                    }
                    if (!--ruleFileStat.st_size) {
                        printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                        return 1;
                    }
                    if ((a = src++[0]) <= ' ') {
                        if (a == 10) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                    }
                    else {
                        a &= 0xDF;
                        if (a & 0xC0) {
                            if (a > 'F') {
                                printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                                return 1;
                            }
                            a ^= 0x40;
                        }
                        a = text2hex[a];
                        if (a > 16) {
                            arg2mask[arg2size] &= 0xF0;
                        }
                        else if (a == 16) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        else {
                            arg2[arg2size] |= a;
                        }
                        if (!ruleFileStat.st_size) {
                            printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                            return 1;
                        }
                        arg2mask[++arg2size] = 0xFF;
                    }
                }
            }
            if (!arg2size) {
                printf("%s: Line %d: ERROR: Syntax error in rule 'replace'\n", ruleFileName, line);
                return 1;

            }
            if (arg2size & 7) {
                memset(arg2mask + arg2size, 0, 8 - (arg2size & 7));
                arg2size += 8 - (arg2size & 7);
            }
            char* i = (char*)PDump + PMBI.RegionSize - arg1size;
            size_t searchingMask = ((size_t*)arg1mask)[0];
            size_t searching = _pext_u64(((size_t*)arg1)[0], searchingMask);
            if (i < (char*)PDump) {
                printf("%s: Line %d: WARNING: Find data size greater than .text segment size\n", ruleFileName, line);
                continue;
            }
            int execCnt = 0;
            do {
                if (_pext_u64((size_t&)(i[0]), searchingMask) == searching) {
                    int j = 8;
                    while (j < arg1size) {
                        if (_pext_u64((size_t&)(i[j]), (size_t&)(arg1mask[j])) != searching) {
                            goto TRY_NEXT;
                        }
                        j += 8;
                    }
                    j = 0;
                    ++execCnt;
                    while (j < arg2size) {
                        (size_t&)(i[j]) = _andn_u64((size_t&)(arg2mask[j]), (size_t&)(i[j])) | _pdep_u64((size_t&)(arg2[j]), (size_t&)(arg2mask[j]));
                        j += 8;
                    }
                    size_t lpNumberOfBytesWritten;
                    WriteProcessMemory(PH, (LPVOID)((size_t)i - (size_t)PDump + (size_t)PMBI.BaseAddress), i, arg2size, &lpNumberOfBytesWritten);
                TRY_NEXT:;
                }
            } while (--i >= (char*)PDump);
            printf("%s: Line %d: NOTE: Replaced %d items\n", ruleFileName, line, execCnt);
        }
        else if (a == 10) {
            ++line;
        }
    } while (--ruleFileStat.st_size >= 0);
    return 0;
}
