#include <iostream>
#include <filesystem>
#include <string>
#include <chrono>
#include <windows.h>
#include <locale>
#include <codecvt>

namespace fs = std::filesystem;

// просто структура хранения для переводов | just a structure for storing translations
struct Messages {
    std::string title;
    std::string startReplace;
    std::string checkingFile;
    std::string fileNotFound;
    std::string sourceFound;
    std::string targetPath;
    std::string replacing;
    std::string success;
    std::string error;
    std::string processComplete;
    std::string pressEnter;
    std::string system32Replace;
    std::string syswow64Replace;
};

// на рус | in ru
Messages russianMessages = {
    "ЗАМЕНА СИСТЕМНЫХ DLL",
    "Начинаем замену DLL",
    "Проверка файла",
    "Файл не найден",
    "Исходный файл найден",
    "Целевой путь",
    "Выполняется замена...",
    "Файл успешно заменён! Время выполнения:",
    "Ошибка при замене файла",
    "Процесс замены завершён!",
    "Нажмите Enter для выхода...",
    "ЗАМЕНА В System32",
    "ЗАМЕНА В SysWOW64"
};

// на англ | in eng
Messages englishMessages = {
    "REPLACING SYSTEM DLLs",
    "Starting DLL replacement",
    "Checking file",
    "File not found",
    "Source file found",
    "Target path",
    "Replacing...",
    "File successfully replaced! Execution time:",
    "Error replacing file",
    "Replacement process completed!",
    "Press Enter to exit...",
    "REPLACING IN System32",
    "REPLACING IN SysWOW64"
};

// глобалка для месседжов | global variable for messages
Messages msgs;

// определение языка | language detection
bool isRussianLocale() {
    LANGID langId = GetSystemDefaultLangID();
    return (langId == 0x0419); // 0x0419 русский | russian
}

// инициализачия меседжов и переводов | initialization of messages and translations
void initMessages() {
    if (isRussianLocale()) {
        msgs = russianMessages;
    } else {
        msgs = englishMessages;
    }
}

// кодировка | encoding
void printStatus(const std::string& message) {
    std::cout << "[*] " << message << std::endl;
}

void printSuccess(const std::string& message) {
    std::cout << "[+] " << message << std::endl;
}

void printError(const std::string& message) {
    std::cerr << "[-] ";
    if (isRussianLocale()) {
        std::cerr << "ОШИБКА: ";
    } else {
        std::cerr << "ERROR: ";
    }
    std::cerr << message << std::endl;
}

void printSeparator() {
    std::cout << "========================================" << std::endl;
}

void ReplaceDll(const fs::path& sourceDir, const fs::path& targetDir, const std::string& dllName) {
    fs::path sourceFile = sourceDir / dllName;
    fs::path targetFile = targetDir / dllName;

    printStatus(msgs.checkingFile + ": " + sourceFile.string());
    
    if (!fs::exists(sourceFile)) {
        printError(msgs.fileNotFound + ": " + sourceFile.string());
        return;
    }

    printStatus(msgs.sourceFound + ": " + sourceFile.string());
    printStatus(msgs.targetPath + ": " + targetFile.string());

    try {
        printStatus(msgs.replacing);
        auto start = std::chrono::high_resolution_clock::now();
        
        fs::copy_file(sourceFile, targetFile, fs::copy_options::overwrite_existing);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        printSuccess(msgs.success + " " + std::to_string(duration.count()) + " ms");
        printSuccess("New file: " + targetFile.string());
    } catch (const fs::filesystem_error& e) {
        printError(msgs.error + ": " + std::string(e.what()));
    }
    
    std::cout << std::endl;
}

int main() {
    // UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
    // инициализация сообщений | messages initialization
    initMessages();
    
    printSeparator();
    printStatus(msgs.title);
    printSeparator();
    
    // пути | paths
    fs::path system32 = "C:/Windows/System32";
    fs::path syswow64 = "C:/Windows/SysWOW64";
    fs::path dll32 = "dll32";
    fs::path dll64 = "dll64";

    // неймы дллок | dll names
    std::string dllName = "Windows.ApplicationModel.Store.dll";

    printStatus(msgs.startReplace + ": " + dllName);
    std::cout << std::endl;

    // замена 32 | replace 32
    printStatus("=== " + msgs.system32Replace + " ===");
    ReplaceDll(dll32, system32, dllName);

    // замена 64 | replace 64
    printStatus("=== " + msgs.syswow64Replace + " ===");
    ReplaceDll(dll64, syswow64, dllName);

    printSeparator();
    printSuccess(msgs.processComplete);
    printSeparator();
    
    // пауза для удобства чисто | pause for convenience only
    printStatus(msgs.pressEnter);
    std::cin.get();
    
    return 0;
}