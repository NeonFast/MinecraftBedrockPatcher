#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>

#pragma comment(lib, "shell32.lib")

// переменная для языка / variable for language
bool isRussian = false;

// обнаружение языка / language detect
void DetectLanguage() {
    LANGID langId = GetSystemDefaultLangID();
    LANGID primaryLang = PRIMARYLANGID(langId);
    isRussian = (primaryLang == LANG_RUSSIAN);
}

// форс консоль / force console
void ForceConsole() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS) && !AllocConsole()) {
        return;
    }
    
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONIN$", "r", stdin);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    
    // UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // очистка буфера / clear buffers
    std::cout.clear();
    std::wcout.clear();
    std::cerr.clear();
    std::wcerr.clear();
}

bool IsUserAnAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup)) {
        
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    
    return isAdmin;
}

void ShowNotification(const std::wstring& title, const std::wstring& message) {
    MessageBoxW(NULL, message.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
}

bool TerminateProcessByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    bool found = false;
    do {
        if (processName == pe32.szExeFile) {
            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                if (TerminateProcess(hProcess, 0)) {
                    found = true;
                }
                CloseHandle(hProcess);
            }
        }
    } while (Process32NextW(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return found;
}

bool ReplaceFile(const std::wstring& source, const std::wstring& target) {
    // проверка файла / check file
    if (GetFileAttributesW(source.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    
    // уборка атрибута а то не сработает / remove attribute or it won't work
    SetFileAttributesW(target.c_str(), FILE_ATTRIBUTE_NORMAL);
    
    // копирование файла / copy file
    if (!CopyFileW(source.c_str(), target.c_str(), FALSE)) {
        return false;
    }
    
    return true;
}

std::wstring GetExecutablePath() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\");
    return std::wstring(buffer).substr(0, pos);
}

int main() {
    // детект языка / detect language
    DetectLanguage();
    
    // консоль / console
    ForceConsole();
    
    // права админа? / admin rights?
    if (!IsUserAnAdmin()) {
        if (isRussian) {
            ShowNotification(L"Ошибка", L"От прав админа запускать надо.");
        } else {
            ShowNotification(L"Error", L"Run as administrator required.");
        }
        system("pause");
        return 1;
    }

    // микрософт сторе / microsoft store
    int terminatedCount = 0;
    std::wstring processes[] = {L"WinStore.App.exe", L"Microsoft.WindowsStore.exe", 
                               L"StoreExperienceHost.exe", L"ApplicationFrameHost.exe"};
    
    for (const auto& process : processes) {
        TerminateProcessByName(process);
    }
    
    Sleep(2000);

    std::wstring exePath = GetExecutablePath();

    std::wstring source64 = exePath + L"\\dll64\\Windows.ApplicationModel.Store.dll";
    std::wstring source32 = exePath + L"\\dll32\\Windows.ApplicationModel.Store.dll";

    std::wstring target64 = L"C:\\Windows\\System32\\Windows.ApplicationModel.Store.dll";
    std::wstring target32 = L"C:\\Windows\\SysWOW64\\Windows.ApplicationModel.Store.dll";

    int successCount = 0;
    int totalFiles = 2;

    // 64 длл / 64 dll
    if (ReplaceFile(source64, target64)) {
        successCount++;
    }

    // 32 длл / 32 dll
    if (ReplaceFile(source32, target32)) {
        successCount++;
    }

    // результаты / results
    if (successCount == totalFiles) {
        if (isRussian) {
            ShowNotification(L"Ура", L"Файлы заменены.");
        } else {
            ShowNotification(L"Success", L"Files replaced successfully.");
        }
    } else {
        if (isRussian) {
            ShowNotification(L"Пиздец", L"Не, ну ты лох.");
        } else {
            ShowNotification(L"Error", L"Failed to replace files.");
        }
        system("pause");
        return 1;
    }

    system("pause");
    return 0;
}