// QuarantineAgent.cpp - Interactive command line tool for the quarantine driver
// 
// Functionality:
// - Quarantine files
// - Release files from quarantine
// - List all quarantined files (filtering ".", "..", and "*.orig" files)
// - Interactive mode with help and banners

#include <iostream>
#include <Windows.h>
#include <fltUser.h>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <functional>
#include <ctime>
#include <direct.h> // For _mkdir
#include <ShlObj.h> // For SHGetFolderPathA

// Link against required libraries
#pragma comment(lib, "FltLib.lib")

// Application constants
#define VERSION "1.0.0"
#define PORT_NAME L"\\BackupPort"

// Command codes (must match the driver)
#define CMD_QUARANTINE 1
#define CMD_RELEASE    2
#define CMD_LIST       3
#define CMD_EXIT       4
#define CMD_HELP       5
#define CMD_VERBOSE    6

// Maximum values for buffers
#define MAX_FILES 100
#define MAX_FILENAME_LENGTH 256

// Console colors
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define COLOR_BOLD    "\033[1m"

// Custom status codes (should match those in your driver)
#define QUARANTINE_SUCCESS                  0x00000000  // STATUS_SUCCESS
#define QUARANTINE_FILE_NOT_FOUND           0xC0000034  // STATUS_OBJECT_NAME_NOT_FOUND
#define QUARANTINE_ACCESS_DENIED            0xC0000022  // STATUS_ACCESS_DENIED
#define QUARANTINE_ALREADY_QUARANTINED      0xC0000035  // STATUS_OBJECT_NAME_COLLISION
#define QUARANTINE_NOT_QUARANTINED          0xC0000034  // STATUS_OBJECT_NAME_NOT_FOUND
#define QUARANTINE_INSUFFICIENT_RESOURCES   0xC000009A  // STATUS_INSUFFICIENT_RESOURCES
#define QUARANTINE_INVALID_PARAMETER        0xC000000D  // STATUS_INVALID_PARAMETER
#define QUARANTINE_DISK_FULL                0xC000007F  // STATUS_DISK_FULL
#define QUARANTINE_INTERNAL_ERROR           0xC00000E5  // STATUS_INTERNAL_ERROR

// Structures
typedef struct _LIST_RESPONSE {
    ULONG FileCount;
    WCHAR Files[MAX_FILES][MAX_FILENAME_LENGTH];
} LIST_RESPONSE, * PLIST_RESPONSE;

typedef struct _COMMAND_MESSAGE {
    ULONG Command;       // Command type
    WCHAR FilePath[MAX_PATH]; // File path for quarantine/release
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

// Global variables
bool g_VerboseMode = false;
HANDLE g_LogFile = INVALID_HANDLE_VALUE;

// Function prototypes
BOOL InitializeConnection(HANDLE* phPort);
std::string GetErrorMessageFromHResult(HRESULT hr);
inline ULONG HResultToNtStatus(HRESULT hr);
VOID DisplayBanner();
VOID DisplayMenu();
VOID DisplayHelp();
VOID DisplayCommandBanner(const char* title);
BOOL QuarantineFile(HANDLE hPort, const std::wstring& filePath);
BOOL ReleaseFile(HANDLE hPort, const std::wstring& fileName);
BOOL ListQuarantinedFiles(HANDLE hPort);
BOOL ShouldDisplayFile(const std::wstring& filename);
VOID LogMessage(const std::string& message, BOOL isError = FALSE);
std::wstring StringToWString(const std::string& str);
std::string WStringToString(const std::wstring& wstr);
BOOL ConfirmAction(const std::string& action);
VOID SetConsoleColor(const char* color);
std::string GetTimeStamp();
VOID InitializeLogging();
VOID CloseLogging();
VOID OutputErrorMessage(HRESULT hr);
VOID OutputSuccessMessage(const char* message);
HRESULT SafeFilterSendMessage(HANDLE hPort, PVOID inBuffer, DWORD inBufferSize,
    PVOID outBuffer, DWORD outBufferSize, PDWORD bytesReturned);

int main() {
    try {
        // Enable ANSI escape sequences for Windows console
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);

        InitializeLogging();

        // Display application banner
        DisplayBanner();

        // Connect to quarantine driver
        HANDLE hPort;
        if (!InitializeConnection(&hPort)) {
            LogMessage("Failed to connect to the quarantine driver", TRUE);
            CloseLogging();
            return 1;
        }

        // Main interactive loop
        bool running = true;
        while (running) {
            DisplayMenu();

            std::string input;
            std::cout << COLOR_BOLD << "Enter your choice: " << COLOR_RESET;
            std::getline(std::cin, input);

            int choice = 0;
            try {
                choice = std::stoi(input);
            }
            catch (...) {
                choice = 0; // Invalid input
            }

            std::cout << std::endl;

            try {
                switch (choice) {
                case CMD_QUARANTINE: {
                    DisplayCommandBanner("QUARANTINE FILE");

                    std::string path;
                    SetConsoleColor(COLOR_CYAN);
                    std::cout << "Enter full path of the file to quarantine: ";
                    SetConsoleColor(COLOR_RESET);
                    std::getline(std::cin, path);

                    if (path.empty()) {
                        SetConsoleColor(COLOR_YELLOW);
                        std::cout << "Operation cancelled. No path provided." << std::endl;
                        SetConsoleColor(COLOR_RESET);
                        break;
                    }

                    if (ConfirmAction("quarantine file '" + path + "'")) {
                        QuarantineFile(hPort, StringToWString(path));
                    }
                    break;
                }
                case CMD_RELEASE: {
                    DisplayCommandBanner("RELEASE FILE");

                    std::string filename;
                    SetConsoleColor(COLOR_CYAN);
                    std::cout << "Enter the file name to release from quarantine: ";
                    SetConsoleColor(COLOR_RESET);
                    std::getline(std::cin, filename);

                    if (filename.empty()) {
                        SetConsoleColor(COLOR_YELLOW);
                        std::cout << "Operation cancelled. No filename provided." << std::endl;
                        SetConsoleColor(COLOR_RESET);
                        break;
                    }

                    if (ConfirmAction("release file '" + filename + "' from quarantine")) {
                        ReleaseFile(hPort, StringToWString(filename));
                    }
                    break;
                }
                case CMD_LIST:
                    DisplayCommandBanner("LIST QUARANTINED FILES");
                    ListQuarantinedFiles(hPort);
                    break;
                case CMD_EXIT:
                    SetConsoleColor(COLOR_GREEN);
                    std::cout << "Exiting EDR Quarantine Agent. Goodbye!" << std::endl;
                    SetConsoleColor(COLOR_RESET);
                    running = false;
                    break;
                case CMD_HELP: // Help option
                    DisplayCommandBanner("HELP INFORMATION");
                    DisplayHelp();
                    break;
                case CMD_VERBOSE: // Toggle verbose mode
                    g_VerboseMode = !g_VerboseMode;
                    SetConsoleColor(COLOR_MAGENTA);
                    std::cout << "Verbose mode " << (g_VerboseMode ? "enabled" : "disabled") << std::endl;
                    SetConsoleColor(COLOR_RESET);
                    break;
                default:
                    SetConsoleColor(COLOR_YELLOW);
                    std::cout << "Invalid choice. Please try again (enter 5 for Help)." << std::endl;
                    SetConsoleColor(COLOR_RESET);
                }
            }
            catch (const std::exception& e) {
                SetConsoleColor(COLOR_RED);
                std::cout << "Error during command execution: " << e.what() << std::endl;
                SetConsoleColor(COLOR_RESET);
                LogMessage(std::string("Exception caught: ") + e.what(), TRUE);
            }
            catch (...) {
                SetConsoleColor(COLOR_RED);
                std::cout << "Unknown error occurred during command execution" << std::endl;
                SetConsoleColor(COLOR_RESET);
                LogMessage("Unknown exception caught", TRUE);
            }

            std::cout << std::endl;
        }

        CloseHandle(hPort);
        CloseLogging();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        LogMessage(std::string("Fatal error: ") + e.what(), TRUE);
        return 1;
    }
    catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        LogMessage("Unknown fatal error", TRUE);
        return 1;
    }
}

// Helper function to safely call FilterSendMessage without using __try/__except
HRESULT SafeFilterSendMessage(HANDLE hPort, PVOID inBuffer, DWORD inBufferSize,
    PVOID outBuffer, DWORD outBufferSize, PDWORD bytesReturned) {
    HRESULT hr = E_FAIL;

    // Use SEH in a separate function to prevent conflicts with C++ exceptions
    __try {
        hr = FilterSendMessage(hPort, inBuffer, inBufferSize, outBuffer, outBufferSize, bytesReturned);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        hr = E_FAIL;
    }

    return hr;
}

// Safely output an error message
VOID OutputErrorMessage(HRESULT hr) {
    try {
        SetConsoleColor(COLOR_RED);
        std::cout << "X Failed with error: 0x" << std::hex << std::uppercase << hr << std::endl;

        // Get a more meaningful error message - but protect against crashes
        std::string errorMsg;
        try {
            errorMsg = GetErrorMessageFromHResult(hr);
            std::cout << "  " << errorMsg << std::endl;
        }
        catch (...) {
            std::cout << "  (Unable to get detailed error message)" << std::endl;
            errorMsg = "Unknown error";
        }

        SetConsoleColor(COLOR_RESET);
    }
    catch (...) {
        // Last resort fallback
        std::cerr << "ERROR 0x" << std::hex << hr << std::endl;
    }
}

// Safely output a success message
VOID OutputSuccessMessage(const char* message) {
    try {
        SetConsoleColor(COLOR_GREEN);
        std::cout << "V " << message << std::endl;
        SetConsoleColor(COLOR_RESET);
    }
    catch (...) {
        // Last resort fallback
        std::cout << "SUCCESS: " << message << std::endl;
    }
}

// Get a user-friendly error message from an HRESULT
std::string GetErrorMessageFromHResult(HRESULT hr) {
    if (SUCCEEDED(hr)) {
        return "Operation completed successfully.";
    }

    // First, check for custom error codes that might have been passed from the driver
    ULONG status = HResultToNtStatus(hr);

    switch (status) {
    case QUARANTINE_SUCCESS:
        return "Operation completed successfully.";
    case QUARANTINE_FILE_NOT_FOUND:
        return "The specified file was not found.";
    case QUARANTINE_ACCESS_DENIED:
        return "Access denied. You may need administrative privileges.";
    case QUARANTINE_ALREADY_QUARANTINED:
        return "The file is already in quarantine.";
    case QUARANTINE_INSUFFICIENT_RESOURCES:
        return "Insufficient system resources to complete the operation.";
    case QUARANTINE_INVALID_PARAMETER:
        return "Invalid parameter or file path.";
    case QUARANTINE_DISK_FULL:
        return "Not enough disk space to complete the operation.";
    case QUARANTINE_INTERNAL_ERROR:
        return "An internal error occurred in the driver.";
    default:
        // For other errors, try to get a system message
        LPVOID lpMsgBuf = nullptr;
        DWORD dw = (hr & 0xFFFF); // Extract error code for FormatMessage

        DWORD result = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            dw,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&lpMsgBuf,
            0, NULL);

        std::string message;

        if (result != 0 && lpMsgBuf != nullptr) {
            message = static_cast<LPSTR>(lpMsgBuf);
            LocalFree(lpMsgBuf);

            // Remove trailing newlines that FormatMessage adds
            while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
                message.pop_back();
            }

            return message;
        }

        // If FormatMessage fails, return the code
        std::stringstream ss;
        ss << "Error code: 0x" << std::hex << std::uppercase << hr;
        return ss.str();
    }
}

// Get a proper NTSTATUS from an HRESULT (for comparison)
inline ULONG HResultToNtStatus(HRESULT hr) {
    // Standard mapping from HRESULT to NTSTATUS for common values
    if (SUCCEEDED(hr))
        return QUARANTINE_SUCCESS;

    // Check if this HRESULT was originally created from an NTSTATUS
    if ((hr & 0xFFFF0000) == 0xC0070000 || // FACILITY_WIN32
        (hr & 0xFFFF0000) == 0x80070000) {
        // Extract the WIN32 error code
        DWORD win32Error = hr & 0xFFFF;
        // Map common error codes
        switch (win32Error) {
        case ERROR_FILE_NOT_FOUND: return QUARANTINE_FILE_NOT_FOUND;
        case ERROR_ACCESS_DENIED: return QUARANTINE_ACCESS_DENIED;
        case ERROR_NOT_ENOUGH_MEMORY: return QUARANTINE_INSUFFICIENT_RESOURCES;
            // Add more mappings as needed
        default: break;
        }
    }

    // For HRESULTs that came directly from NTSTATUS (via HRESULT_FROM_NT)
    if ((hr & 0xFFFF0000) == 0xC0000000) {
        // It's likely already an NTSTATUS with the HRESULT facility bits
        return static_cast<ULONG>(hr);
    }

    // Default case
    return 0xC0000001; // Equivalent to STATUS_UNSUCCESSFUL
}

// Initialize connection to the quarantine driver
BOOL InitializeConnection(HANDLE* phPort) {
    HRESULT hr = FilterConnectCommunicationPort(
        PORT_NAME,
        0,
        NULL,
        0,
        NULL,
        phPort
    );

    if (FAILED(hr)) {
        SetConsoleColor(COLOR_RED);
        std::cout << "Failed to connect to quarantine driver: 0x"
            << std::hex << std::uppercase << hr << std::endl;
        std::cout << "Make sure the quarantine driver service is running." << std::endl;
        SetConsoleColor(COLOR_RESET);

        LogMessage("Connection failure: 0x" + std::to_string(hr), TRUE);
        return FALSE;
    }

    if (g_VerboseMode) {
        LogMessage("Successfully connected to quarantine driver");
    }

    return TRUE;
}

// Display application banner
VOID DisplayBanner() {
    std::cout << std::endl;
    SetConsoleColor(COLOR_BOLD);
    SetConsoleColor(COLOR_CYAN);
    std::cout << "+=====================================================+" << std::endl;
    std::cout << "|                                                     |" << std::endl;
    std::cout << "|            EDR QUARANTINE AGENT v" << std::left << std::setw(10) << VERSION << "         |" << std::endl;
    std::cout << "|                                                     |" << std::endl;
    std::cout << "+=====================================================+" << std::endl;
    SetConsoleColor(COLOR_BOLD);
    SetConsoleColor(COLOR_RESET);
    std::cout << std::endl;
}

// Display command-specific banner
VOID DisplayCommandBanner(const char* title) {
    SetConsoleColor(COLOR_BOLD);
    std::cout << "+-------------------------------------------+" << std::endl;

    // Calculate centering for the title
    size_t titleLen = strlen(title);
    int padding = static_cast<int>((41 - titleLen) / 2);  // Fix for C4267 warning
    std::cout << "|" << std::string(padding, ' ') << title << std::string(41 - padding - titleLen, ' ') << "|" << std::endl;

    std::cout << "+-------------------------------------------+" << std::endl;
    SetConsoleColor(COLOR_RESET);
    std::cout << std::endl;
}

// Display the main menu
VOID DisplayMenu() {
    SetConsoleColor(COLOR_BOLD);
    std::cout << "+---------------------------------------+" << std::endl;
    std::cout << "|         AVAILABLE COMMANDS            |" << std::endl;
    std::cout << "+---------------------------------------+" << std::endl;
    SetConsoleColor(COLOR_RESET);

    std::cout << "  1. " << COLOR_CYAN << "Quarantine a file" << COLOR_RESET << std::endl;
    std::cout << "  2. " << COLOR_GREEN << "Release a file from quarantine" << COLOR_RESET << std::endl;
    std::cout << "  3. " << COLOR_BLUE << "List quarantined files" << COLOR_RESET << std::endl;
    std::cout << "  4. " << COLOR_YELLOW << "Exit" << COLOR_RESET << std::endl;
    std::cout << "  5. " << COLOR_MAGENTA << "Help" << COLOR_RESET << std::endl;
    std::cout << "  6. " << COLOR_WHITE << "Toggle verbose mode" << COLOR_RESET << std::endl;
    std::cout << std::endl;
}

// Display help information
VOID DisplayHelp() {
    std::cout << COLOR_BOLD << "Interactive Mode Commands:" << COLOR_RESET << std::endl << std::endl;

    std::cout << COLOR_CYAN << "  1. Quarantine a file" << COLOR_RESET << std::endl;
    std::cout << "     Moves a suspicious file to quarantine storage" << std::endl;
    std::cout << "     You'll need to provide the full path to the file" << std::endl << std::endl;

    std::cout << COLOR_GREEN << "  2. Release a file from quarantine" << COLOR_RESET << std::endl;
    std::cout << "     Restores a previously quarantined file" << std::endl;
    std::cout << "     You only need to provide the filename (not the path)" << std::endl << std::endl;

    std::cout << COLOR_BLUE << "  3. List quarantined files" << COLOR_RESET << std::endl;
    std::cout << "     Shows all files currently in quarantine" << std::endl;
    std::cout << "     Note: Directory entries (. and ..) and .orig files are filtered out" << std::endl << std::endl;

    std::cout << COLOR_YELLOW << "  4. Exit" << COLOR_RESET << std::endl;
    std::cout << "     Closes the application" << std::endl << std::endl;

    std::cout << COLOR_MAGENTA << "  5. Help" << COLOR_RESET << std::endl;
    std::cout << "     Displays this help information" << std::endl << std::endl;

    std::cout << COLOR_WHITE << "  6. Toggle verbose mode" << COLOR_RESET << std::endl;
    std::cout << "     Enables/disables detailed operation information" << std::endl << std::endl;

    std::cout << COLOR_BOLD << "Notes:" << COLOR_RESET << std::endl;
    std::cout << "- This tool requires administrative privileges" << std::endl;
    std::cout << "- The quarantine driver service must be running" << std::endl;
    std::cout << "- All actions are logged to the logs folder" << std::endl;
    std::cout << std::endl;
}

// Determine if a file should be displayed in the list
BOOL ShouldDisplayFile(const std::wstring& filename) {
    // Safety check for null or empty filename
    if (filename.empty()) {
        return FALSE;
    }

    // Filter out "." and ".." directory entries
    if (filename == L"." || filename == L"..") {
        return FALSE;
    }

    // Filter out files ending with ".orig"
    if (filename.length() >= 5) {
        std::wstring extension = filename.substr(filename.length() - 5);
        if (extension == L".orig") {
            return FALSE;
        }
    }

    return TRUE;
}

// Quarantine a file
BOOL QuarantineFile(HANDLE hPort, const std::wstring& filePath) {
    if (g_VerboseMode) {
        LogMessage("Attempting to quarantine file: " + WStringToString(filePath));
    }

    // Input validation
    if (filePath.empty() || filePath.length() >= MAX_PATH) {
        OutputErrorMessage(HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER));
        LogMessage("Invalid file path for quarantine", TRUE);
        return FALSE;
    }

    COMMAND_MESSAGE cmd = { CMD_QUARANTINE };
    ZeroMemory(cmd.FilePath, sizeof(cmd.FilePath)); // Clear buffer first
    wcsncpy_s(cmd.FilePath, filePath.c_str(), MAX_PATH - 1);
    DWORD bytesReturned = 0;
    WCHAR OutBuff[1];
    // Call the driver using our safe helper function
    HRESULT hr = SafeFilterSendMessage(hPort, &cmd, sizeof(cmd), OutBuff, 0, &bytesReturned);

    if (SUCCEEDED(hr)) {
        OutputSuccessMessage("File quarantined successfully.");
        LogMessage("Successfully quarantined file: " + WStringToString(filePath));
        return TRUE;
    }
    else {
        OutputErrorMessage(hr);

        // Get error message safely
        std::string errorMsg;
        try {
            errorMsg = GetErrorMessageFromHResult(hr);
        }
        catch (...) {
            errorMsg = "Unknown error";
        }

        LogMessage("Failed to quarantine file: 0x" + std::to_string(hr) + " - " +
            WStringToString(filePath) + " - " + errorMsg, TRUE);
        return FALSE;
    }
}

// Release a file from quarantine
BOOL ReleaseFile(HANDLE hPort, const std::wstring& fileName) {
    if (g_VerboseMode) {
        LogMessage("Attempting to release file: " + WStringToString(fileName));
    }

    // Input validation
    if (fileName.empty() || fileName.length() >= MAX_PATH) {
        OutputErrorMessage(HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER));
        LogMessage("Invalid file name for release", TRUE);
        return FALSE;
    }

    COMMAND_MESSAGE cmd = { CMD_RELEASE };
    ZeroMemory(cmd.FilePath, sizeof(cmd.FilePath)); // Clear buffer first
    wcsncpy_s(cmd.FilePath, fileName.c_str(), MAX_PATH - 1);
    DWORD bytesReturned = 0;
    WCHAR OutBuff[1];
    // Call the driver using our safe helper function
    HRESULT hr = SafeFilterSendMessage(hPort, &cmd, sizeof(cmd), OutBuff, 0, &bytesReturned);

    if (SUCCEEDED(hr)) {
        OutputSuccessMessage("File released successfully.");
        LogMessage("Successfully released file: " + WStringToString(fileName));
        return TRUE;
    }
    else {
        OutputErrorMessage(hr);

        // Get error message safely
        std::string errorMsg;
        try {
            errorMsg = GetErrorMessageFromHResult(hr);
        }
        catch (...) {
            errorMsg = "Unknown error";
        }

        LogMessage("Failed to release file: 0x" + std::to_string(hr) + " - " +
            WStringToString(fileName) + " - " + errorMsg, TRUE);
        return FALSE;
    }
}

// List all quarantined files
BOOL ListQuarantinedFiles(HANDLE hPort) {
    if (g_VerboseMode) {
        LogMessage("Listing quarantined files");
    }

    COMMAND_MESSAGE cmd = { CMD_LIST };

    // Allocate buffer for response
    const size_t bufferSize = sizeof(LIST_RESPONSE);
    LIST_RESPONSE* response = static_cast<LIST_RESPONSE*>(malloc(bufferSize));

    if (!response) {
        SetConsoleColor(COLOR_RED);
        std::cout << "X Memory allocation failed!" << std::endl;
        SetConsoleColor(COLOR_RESET);

        LogMessage("Memory allocation failed for list operation", TRUE);
        return FALSE;
    }

    // Initialize memory to prevent reading uninitialized data
    ZeroMemory(response, bufferSize);

    ULONG bytesReturned = 0;

    // Call the driver using our safe helper function
    HRESULT hr = SafeFilterSendMessage(hPort, &cmd, sizeof(cmd), response, static_cast<DWORD>(bufferSize), &bytesReturned);

    if (SUCCEEDED(hr) && bytesReturned >= sizeof(ULONG)) {
        // Ensure the data is valid before using it
        if (response->FileCount > MAX_FILES) {
            SetConsoleColor(COLOR_RED);
            std::cout << "X Invalid file count received from driver!" << std::endl;
            SetConsoleColor(COLOR_RESET);
            free(response);
            LogMessage("Invalid file count received: " + std::to_string(response->FileCount), TRUE);
            return FALSE;
        }

        // Create filtered list of files
        std::vector<std::wstring> filteredFiles;
        for (ULONG i = 0; i < response->FileCount; ++i) {
            // Ensure the filename is properly null-terminated
            response->Files[i][MAX_FILENAME_LENGTH - 1] = L'\0';

            if (ShouldDisplayFile(response->Files[i])) {
                filteredFiles.push_back(response->Files[i]);
            }
            else if (g_VerboseMode) {
                LogMessage("Filtered out file: " + WStringToString(response->Files[i]));
            }
        }

        ULONG filteredCount = static_cast<ULONG>(filteredFiles.size());

        if (filteredCount > 0) {
            // Calculate the width needed for the index column based on the number of files
            int indexWidth = 1;
            if (filteredCount >= 10) indexWidth = 2;
            if (filteredCount >= 100) indexWidth = 3;

            for (ULONG i = 0; i < filteredCount; ++i) {
                SetConsoleColor(COLOR_BLUE);
                std::cout << "  " << std::setw(indexWidth) << (i + 1) << ". ";
                SetConsoleColor(COLOR_RESET);

                // Safe wide character output
                std::string narrowFilename = WStringToString(filteredFiles[i]);
                std::cout << narrowFilename << std::endl;

                if (g_VerboseMode) {
                    LogMessage("Listed file: " + narrowFilename);
                }
            }

            SetConsoleColor(COLOR_BOLD);
            std::cout << std::endl << "  Total: " << filteredCount << " file(s)";
            if (filteredCount < response->FileCount) {
                std::cout << " (" << (response->FileCount - filteredCount) << " filtered out)";
            }
            std::cout << std::endl;
            SetConsoleColor(COLOR_RESET);
        }
        else {
            SetConsoleColor(COLOR_YELLOW);
            std::cout << "  No files in quarantine.";
            if (response->FileCount > 0) {
                std::cout << " (" << response->FileCount << " system files filtered out)";
            }
            std::cout << std::endl;
            SetConsoleColor(COLOR_RESET);
        }

        LogMessage("Successfully listed " + std::to_string(filteredCount) + " quarantined files (" +
            std::to_string(response->FileCount - filteredCount) + " filtered)");
    }
    else {
        OutputErrorMessage(hr);

        // Get error message safely
        std::string errorMsg;
        try {
            errorMsg = GetErrorMessageFromHResult(hr);
        }
        catch (...) {
            errorMsg = "Unknown error";
        }

        LogMessage("Failed to list quarantined files: 0x" + std::to_string(hr) + " - " + errorMsg, TRUE);
    }

    free(response);
    return SUCCEEDED(hr);
}

// Log a message to the log file
VOID LogMessage(const std::string& message, BOOL isError) {
    // Check if the log file handle is valid
    if (g_LogFile == INVALID_HANDLE_VALUE) {
        // Try to initialize logging again
        InitializeLogging();

        // If still invalid, return
        if (g_LogFile == INVALID_HANDLE_VALUE) return;
    }

    try {
        std::string logEntry = GetTimeStamp() + " [" + (isError ? "ERROR" : "INFO") + "] " + message + "\r\n";

        DWORD bytesWritten = 0;
        BOOL result = WriteFile(g_LogFile, logEntry.c_str(), static_cast<DWORD>(logEntry.length()), &bytesWritten, NULL);

        // If write failed, try reopening the log file
        if (!result || bytesWritten != logEntry.length()) {
            CloseHandle(g_LogFile);
            g_LogFile = INVALID_HANDLE_VALUE;
            InitializeLogging();

            if (g_LogFile != INVALID_HANDLE_VALUE) {
                WriteFile(g_LogFile, logEntry.c_str(), static_cast<DWORD>(logEntry.length()), &bytesWritten, NULL);
            }
        }

        if (g_VerboseMode && !isError) {
            SetConsoleColor(COLOR_MAGENTA);
            std::cout << "[INFO] " << message << std::endl;
            SetConsoleColor(COLOR_RESET);
        }
    }
    catch (...) {
        // Silent failure for logging - don't crash the app if logging fails
    }
}

// Convert std::string to std::wstring - simplified version
std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";

    try {
        // Calculate needed buffer size
        int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        if (size <= 0) return L""; // Error in sizing

        // Create wstring of required size
        std::wstring result(size, 0);

        // Do the conversion
        if (MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size) <= 0) {
            return L""; // Error in conversion
        }

        // Remove the null terminator
        result.resize(size - 1);

        return result;
    }
    catch (...) {
        return L""; // Return empty string on any error
    }
}

// Convert std::wstring to std::string - simplified version
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";

    try {
        // Calculate needed buffer size
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return ""; // Error in sizing

        // Create string of required size
        std::string result(size, 0);

        // Do the conversion
        if (WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr) <= 0) {
            return ""; // Error in conversion
        }

        // Remove the null terminator
        result.resize(size - 1);

        return result;
    }
    catch (...) {
        return ""; // Return empty string on any error
    }
}

// Ask for confirmation before performing an action
BOOL ConfirmAction(const std::string& action) {
    SetConsoleColor(COLOR_YELLOW);
    std::cout << "Are you sure you want to " << action << "? [y/N]: ";
    SetConsoleColor(COLOR_RESET);

    std::string response;
    std::getline(std::cin, response);

    std::transform(response.begin(), response.end(), response.begin(), ::tolower);
    return (response == "y" || response == "yes");
}

// Set the console text color
VOID SetConsoleColor(const char* color) {
    try {
        std::cout << color;
    }
    catch (...) {
        // Ignore color setting errors
    }
}

// Get current timestamp for logging
std::string GetTimeStamp() {
    try {
        time_t now = time(0);
        struct tm timeinfo;
        char buffer[25];

        localtime_s(&timeinfo, &now);
        strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S]", &timeinfo);

        return std::string(buffer);
    }
    catch (...) {
        return "[timestamp error]";
    }
}

// Initialize the log file in Documents\Agent\Logs folder
VOID InitializeLogging() {
    try {
        // Get the path to the Documents folder
        char documentsPath[MAX_PATH];
        if (FAILED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsPath))) {
            std::cerr << "Failed to get Documents folder path. Logging will be disabled." << std::endl;
            g_LogFile = INVALID_HANDLE_VALUE;
            return;
        }

        // Create full path to Agent\Logs folder
        std::string logDirPath = std::string(documentsPath) + "\\Agent\\Logs";

        // Create the Agent directory first
        std::string agentDirPath = std::string(documentsPath) + "\\Agent";
        if (_mkdir(agentDirPath.c_str()) != 0 && errno != EEXIST) {
            // Try Windows API if _mkdir fails
            if (!CreateDirectoryA(agentDirPath.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                std::cerr << "Failed to create Agent directory in Documents. Logging will be disabled." << std::endl;
                g_LogFile = INVALID_HANDLE_VALUE;
                return;
            }
        }

        // Now create the Logs subdirectory
        if (_mkdir(logDirPath.c_str()) != 0 && errno != EEXIST) {
            // Try Windows API if _mkdir fails
            if (!CreateDirectoryA(logDirPath.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                std::cerr << "Failed to create Logs directory in Documents\\Agent. Logging will be disabled." << std::endl;
                g_LogFile = INVALID_HANDLE_VALUE;
                return;
            }
        }

        // Create log filename with timestamp
        time_t now = time(0);
        struct tm timeinfo;
        char buffer[MAX_PATH];

        localtime_s(&timeinfo, &now);
        snprintf(buffer, sizeof(buffer), "%s\\QuarantineAgent_%04d%02d%02d.log",
            logDirPath.c_str(),
            timeinfo.tm_year + 1900,
            timeinfo.tm_mon + 1,
            timeinfo.tm_mday);

        // Output the path we're trying to use
        std::cout << "Creating log file at: " << buffer << std::endl;

        // Open log file
        g_LogFile = CreateFileA(
            buffer,
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (g_LogFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "Failed to open log file: " << buffer << " (Error: " << error << ")" << std::endl;
            return;
        }

        // Add a separator for new session
        std::string sessionStart = "\r\n" + GetTimeStamp() + " [INFO] ========== NEW SESSION ==========\r\n";
        DWORD bytesWritten;
        if (!WriteFile(g_LogFile, sessionStart.c_str(), static_cast<DWORD>(sessionStart.size()), &bytesWritten, NULL)) {
            std::cerr << "Failed to write to log file (Error: " << GetLastError() << ")" << std::endl;
            CloseHandle(g_LogFile);
            g_LogFile = INVALID_HANDLE_VALUE;
        }
        else {
            std::cout << "Log file initialized successfully." << std::endl;
        }
    }
    catch (...) {
        // If logging initialization fails, continue without logging
        std::cerr << "Exception during log initialization" << std::endl;
        g_LogFile = INVALID_HANDLE_VALUE;
    }
}

// Close the log file
VOID CloseLogging() {
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        try {
            std::string sessionEnd = GetTimeStamp() + " [INFO] ========== SESSION ENDED ==========\r\n\r\n";
            DWORD bytesWritten;
            WriteFile(g_LogFile, sessionEnd.c_str(), static_cast<DWORD>(sessionEnd.size()), &bytesWritten, NULL);

            CloseHandle(g_LogFile);
            std::cout << "Log file closed." << std::endl;
        }
        catch (...) {
            // Ignore errors during shutdown
        }

        g_LogFile = INVALID_HANDLE_VALUE;
    }
}