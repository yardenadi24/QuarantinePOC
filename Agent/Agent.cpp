// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fltUser.h> // Link against FltLib.lib
#include <string>

#define PORT_NAME L"\\QuarantineDrv"


// Command codes (must match the driver)
#define CMD_QUARANTINE 1
#define CMD_RELEASE    2
#define CMD_LIST       3


// Input message structure (must match the driver)
typedef struct _COMMAND_MESSAGE {
	ULONG Command;       // Command type
	WCHAR FilePath[MAX_PATH]; // File path for quarantine/release
} COMMAND_MESSAGE, * PCOMMAND_MESSAGE;

// Output structure for CMD_LIST response (must match the driver)
typedef struct _LIST_RESPONSE {
	ULONG FileCount;     // Number of files
	WCHAR FileNames[1][MAX_PATH]; // Array of file names
} LIST_RESPONSE, * PLIST_RESPONSE;

int main()
{
   printf("Quarantine communication tester!\n");

   HANDLE hPort;
   HRESULT hr = FilterConnectCommunicationPort(
	   L"\\BackupPort",
	   0,
	   NULL,
	   0,
	   NULL,
	   &hPort
   );

   if (FAILED(hr))
   {
	   printf("Failed connecting to communication port: 0x%X\n",hr);
	   return -1;
   }

   bool Running = true;
   while (Running) {
	   std::cout << "EDR Quarantine Tool" << std::endl;
	   std::cout << "1. Quarantine a file" << std::endl;
	   std::cout << "2. Release a file from quarantine" << std::endl;
	   std::cout << "3. List quarantined files" << std::endl;
	   std::cout << "4. Exit" << std::endl;
	   std::cout << "Enter your choice: ";
	   int choice;
	   std::cin >> choice;
	   std::cin.ignore(); // Ignore the newline character after reading the choice
   
	   switch (choice)
	   {
	   case CMD_QUARANTINE:
	   {
		   std::string Path;
		   std::cout << "Enter full path of the file to quarantine (e.g., C:\\Path\\file.txt): ";
		   std::getline(std::cin, Path);
		   std::wstring wPath(Path.begin(), Path.end());
		   COMMAND_MESSAGE Cmd = { CMD_QUARANTINE };
		   wcsncpy_s(Cmd.FilePath, wPath.c_str(), MAX_PATH);
		   hr = FilterSendMessage(hPort, &Cmd, sizeof(Cmd), NULL, 0, NULL);
		   if (SUCCEEDED(hr)) {
			   std::cout << "File quarantined successfully." << std::endl;
		   }
		   else {
			   std::cerr << "Failed to quarantine file: 0x" << std::hex << hr << std::endl;
		   }
		   break;
	   }
	   case CMD_RELEASE:
	   {
		   std::string Filename;
		   std::cout << "Enter the file name to release from quarantine (e.g., file.txt): ";
		   std::getline(std::cin, Filename);
		   std::wstring wFilename(Filename.begin(), Filename.end());
		   COMMAND_MESSAGE Cmd = { CMD_RELEASE };
		   wcsncpy_s(Cmd.FilePath, wFilename.c_str(), 260);
		   hr = FilterSendMessage(hPort, &Cmd, sizeof(Cmd), NULL, 0, NULL);
		   if (SUCCEEDED(hr)) {
			   std::cout << "File released successfully." << std::endl;
		   }
		   else {
			   std::cerr << "Failed to release file: 0x" << std::hex << hr << std::endl;
		   }
		   break;
	   }
	   case CMD_LIST:
	   {
		   COMMAND_MESSAGE Cmd = { CMD_LIST };
		   const size_t BufferSize = 65536; // 64KB buffer for response
		   BYTE* Buffer = new BYTE[BufferSize];
		   ULONG BytesReturned;
		   hr = FilterSendMessage(hPort, &Cmd, sizeof(Cmd), Buffer, BufferSize, &BytesReturned);
		   if (SUCCEEDED(hr) && BytesReturned >= sizeof(ULONG)) {
			   ULONG FileCount = *(ULONG*)Buffer;
			   std::cout << "Quarantined files (" << FileCount << "):" << std::endl;
			   WCHAR* NamesPtr = (WCHAR*)(Buffer + sizeof(ULONG));
			   for (ULONG i = 0; i < FileCount; ++i) {
				   std::wcout << (NamesPtr + i * 260) << std::endl;
			   }
		   }
		   else if (SUCCEEDED(hr)) {
			   std::cout << "No files in quarantine." << std::endl;
		   }
		   else {
			   std::cerr << "Failed to list quarantined files: 0x" << std::hex << hr << std::endl;
		   }
		   delete[] Buffer;
		   break;
	   }
	   case 4:
		   Running = FALSE;
	   default:
		   std::cout << "Invalid choice. Please try again." << std::endl;
	   }
   
   
   }
   
   if (hPort != NULL)
   {
		CloseHandle(hPort);
   }

   return 0;
}
