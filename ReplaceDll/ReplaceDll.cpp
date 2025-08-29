#include <iostream>
#include <filesystem>
#include <string>
#include <chrono>
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

// Функция для включения привилегии
bool EnablePrivilege(LPCTSTR lpszPrivilege) {
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(nullptr, lpszPrivilege, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) &&
        GetLastError() == ERROR_SUCCESS;

    CloseHandle(hToken);
    return result;
}

// Функция для получения SID текущего пользователя
PSID GetUserSid() {
    HANDLE hToken = nullptr;
    PTOKEN_USER pTokenUser = nullptr;
    DWORD dwBufferSize = 0;
    PSID pSid = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return nullptr;
    }

    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwBufferSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return nullptr;
    }

    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwBufferSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return nullptr;
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        DWORD sidLength = GetLengthSid(pTokenUser->User.Sid);
        pSid = LocalAlloc(LPTR, sidLength);
        if (pSid) {
            CopySid(sidLength, pSid, pTokenUser->User.Sid);
        }
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);
    return pSid;
}

// Функция для установки владения файлом
bool TakeOwnership(const std::wstring& filePath) {
    // Включаем необходимые привилегии
    EnablePrivilege(SE_TAKE_OWNERSHIP_NAME);
    EnablePrivilege(SE_RESTORE_NAME);
    EnablePrivilege(SE_BACKUP_NAME);

    // Открываем файл с максимальными правами
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        READ_CONTROL | WRITE_DAC | WRITE_OWNER,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // Для работы с системными файлами
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::wcout << L"[-] Failed to open file. Error: " << error << std::endl;
        return false;
    }

    PSID pSid = GetUserSid();
    if (!pSid) {
        CloseHandle(hFile);
        return false;
    }

    // Установка владельца
    DWORD result = SetSecurityInfo(
        hFile,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        pSid,
        nullptr,
        nullptr,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        std::wcout << L"[-] SetSecurityInfo failed. Error: " << result << std::endl;
        LocalFree(pSid);
        CloseHandle(hFile);
        return false;
    }

    // Назначение полных прав для текущего пользователя
    PACL pOldDACL = nullptr, pNewDACL = nullptr;
    PSECURITY_DESCRIPTOR pSD = nullptr;

    result = GetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &pOldDACL, nullptr, &pSD);

    if (result == ERROR_SUCCESS) {
        EXPLICIT_ACCESS_W ea;
        ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = (LPWSTR)pSid;

        result = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
        if (result == ERROR_SUCCESS) {
            result = SetSecurityInfo(hFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pNewDACL, nullptr);
            if (pNewDACL) LocalFree(pNewDACL);
        }
        if (pSD) LocalFree(pSD);
    }

    LocalFree(pSid);
    CloseHandle(hFile);
    return (result == ERROR_SUCCESS);
}

// Функция для отключения File System Redirection
void DisableRedirection(PVOID* OldValue) {
    *OldValue = nullptr;

    HMODULE hMod = GetModuleHandle(TEXT("kernel32.dll"));
    if (hMod == NULL) {
        return;
    }

#pragma warning(push)
#pragma warning(disable: 6387)
    FARPROC proc = GetProcAddress(hMod, "Wow64DisableWow64FsRedirection");
    if (proc == NULL) {
        return;
    }

    typedef BOOL(WINAPI* Wow64DisableWow64FsRedirection_t)(PVOID*);
    Wow64DisableWow64FsRedirection_t pWow64DisableWow64FsRedirection =
        (Wow64DisableWow64FsRedirection_t)proc;

    pWow64DisableWow64FsRedirection(OldValue);
#pragma warning(pop)
}

// Функция для восстановления File System Redirection
void RevertRedirection(PVOID OldValue) {
    if (OldValue == nullptr) return;

    HMODULE hMod = GetModuleHandle(TEXT("kernel32.dll"));
    if (hMod == NULL) return;

#pragma warning(push)
#pragma warning(disable: 6387)
    FARPROC proc = GetProcAddress(hMod, "Wow64RevertWow64FsRedirection");
    if (proc == NULL) return;

    typedef BOOL(WINAPI* Wow64RevertWow64FsRedirection_t)(PVOID);
    Wow64RevertWow64FsRedirection_t pWow64RevertWow64FsRedirection =
        (Wow64RevertWow64FsRedirection_t)proc;

    pWow64RevertWow64FsRedirection(OldValue);
#pragma warning(pop)
}

// Функция для поиска процессов, использующих файл
std::vector<DWORD> FindProcessesUsingFile(const std::wstring& fileName) {
    std::vector<DWORD> processIds;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processIds;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return processIds;
    }

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            HMODULE hMods[1024];
            DWORD cbNeeded;

            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    wchar_t szModName[MAX_PATH];

                    if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                        std::wstring modName(szModName);
                        if (modName.find(fileName) != std::wstring::npos) {
                            processIds.push_back(pe32.th32ProcessID);
                            break;
                        }
                    }
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return processIds;
}

// Функция для получения имени процесса по ID
std::wstring GetProcessName(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return L"Unknown";
    }

    wchar_t processName[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
        std::wstring name(processName);
        size_t pos = name.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            name = name.substr(pos + 1);
        }
        CloseHandle(hProcess);
        return name;
    }

    CloseHandle(hProcess);
    return L"Unknown";
}

// Функция для завершения процесса
bool TerminateProcessById(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        return false;
    }

    bool result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    return result;
}

// Улучшенная функция замены с take ownership и закрытием процессов
bool ReplaceDllWithOwnership(const fs::path& sourceDir, const fs::path& targetDir, const std::string& dllName) {
    fs::path sourceFile = sourceDir / dllName;
    fs::path targetFile = targetDir / dllName;

    std::wcout << L"[*] Checking file: " << sourceFile.wstring() << std::endl;

    if (!fs::exists(sourceFile)) {
        std::wcout << L"[-] ERROR: File not found: " << sourceFile.wstring() << std::endl;
        return false;
    }

    std::wcout << L"[*] Source file found: " << sourceFile.wstring() << std::endl;
    std::wcout << L"[*] Target path: " << targetFile.wstring() << std::endl;

    // Проверяем, используется ли файл
    std::wstring fileName(dllName.begin(), dllName.end());
    std::vector<DWORD> processes = FindProcessesUsingFile(fileName);

    if (!processes.empty()) {
        std::wcout << L"[*] File is being used by following processes:" << std::endl;
        for (DWORD pid : processes) {
            std::wcout << L"    - PID: " << pid << L", Name: " << GetProcessName(pid) << std::endl;
        }

        std::wcout << L"[*] Attempting to terminate processes..." << std::endl;
        for (DWORD pid : processes) {
            if (TerminateProcessById(pid)) {
                std::wcout << L"[+] Successfully terminated process PID: " << pid << std::endl;
            }
            else {
                std::wcout << L"[-] Failed to terminate process PID: " << pid << std::endl;
            }
        }

        // Ждем немного, чтобы процессы действительно завершились
        Sleep(1000);
    }

    try {
        std::wcout << L"[*] Taking ownership and setting permissions..." << std::endl;

        // Получаем владение файлом
        if (!TakeOwnership(targetFile.wstring())) {
            std::wcout << L"[-] WARNING: Failed to take ownership of " << targetFile.wstring() << std::endl;
        }

        std::wcout << L"[*] Replacing..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();

        // Отключаем редирект для 32-битных приложений
        PVOID OldValue = nullptr;
        DisableRedirection(&OldValue);

        fs::copy_file(sourceFile, targetFile, fs::copy_options::overwrite_existing);

        // Восстанавливаем редирект
        RevertRedirection(OldValue);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::wcout << L"[+] File successfully replaced! Execution time: "
            << duration.count() << L" ms" << std::endl;
        std::wcout << L"[+] New file: " << targetFile.wstring() << std::endl;
        return true;
    }
    catch (const fs::filesystem_error& e) {
        std::wcout << L"[-] ERROR replacing file: " << std::wstring(e.what(), e.what() + strlen(e.what())) << std::endl;
        return false;
    }

    std::wcout << std::endl;
    return false;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Проверяем права администратора
    EnablePrivilege(SE_DEBUG_NAME);

    std::wcout << L"========================================" << std::endl;
    std::wcout << L"[*] REPLACING SYSTEM DLLs" << std::endl;
    std::wcout << L"========================================" << std::endl;

    fs::path system32 = L"C:/Windows/System32";
    fs::path syswow64 = L"C:/Windows/SysWOW64";
    fs::path dll32 = L"dll32";
    fs::path dll64 = L"dll64";

    std::string dllName = "Windows.ApplicationModel.Store.dll";

    std::wcout << L"[*] Starting DLL replacement: " << std::wstring(dllName.begin(), dllName.end()) << std::endl;
    std::wcout << std::endl;

    bool success32 = false, success64 = false;

    std::wcout << L"[*] === REPLACING IN System32 ===" << std::endl;
    success32 = ReplaceDllWithOwnership(dll32, system32, dllName);

    std::wcout << L"[*] === REPLACING IN SysWOW64 ===" << std::endl;
    success64 = ReplaceDllWithOwnership(dll64, syswow64, dllName);

    std::wcout << L"========================================" << std::endl;
    if (success32 && success64) {
        std::wcout << L"[+] Replacement process completed successfully!" << std::endl;
    }
    else {
        std::wcout << L"[-] Replacement process completed with errors!" << std::endl;
    }
    std::wcout << L"========================================" << std::endl;

    std::wcout << L"[*] Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}