// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fltUser.h> // Link against FltLib.lib

#define PORT_NAME L"\\QuarantineDrv"

// Define the command message structure as shared with the kernel mode
typedef enum _COMMAND_TYPE {
	QuarantineFile,
	UnquarantineFile,
	ListQuarantinedFiles
} COMMAND_TYPE;

typedef struct _COMMAND_MESSAGE {
	COMMAND_TYPE CommandType;
	WCHAR FilePath[MAX_PATH]; // Used for Quarantine/Unquarantine operations
} COMMAND_MESSAGE;

typedef struct _RESPONSE_MESSAGE {
	NTSTATUS Status;
	ULONG DataLength; // Used for ListQuarantinedFiles to indicate buffer length
	WCHAR Data[];     // Used for ListQuarantinedFiles to return file paths
} RESPONSE_MESSAGE;

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

   COMMAND_MESSAGE CmdMessage;
   CmdMessage.CommandType = QuarantineFile;
   wcscpy_s(CmdMessage.FilePath, MAX_PATH, L"C:\\Test.txt");
   RESPONSE_MESSAGE Response;
   DWORD BytesReturned;
   hr = FilterSendMessage(
	   hPort,
	   &CmdMessage,
	   sizeof(CmdMessage),
	   &Response,
	   sizeof(Response),
	   &BytesReturned
   );

   if (SUCCEEDED(hr))
   {
	   printf("Received response: %ws \n", Response.Data);
   }
   else {
	   printf("Failed to receive response: (0x%X)", hr);
   }

   CloseHandle(hPort);

   return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
