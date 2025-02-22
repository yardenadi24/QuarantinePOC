#include "drv.h"

PFLT_FILTER g_pFilter;
PFLT_PORT g_pServerPort;
PFLT_PORT g_pClientPort;
PDRIVER_OBJECT g_pDriverObject;
PUNICODE_STRING g_pQuarantineDirPath;



NTSTATUS
CompleteRequest(
	PIRP Irp,
	NTSTATUS Status, // Default status for IRP
	ULONG_PTR Info				  // Default info which is used for (written usually)
)
{
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

extern "C"
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	LOG("Enter");

	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObj = NULL;
	UNICODE_STRING Symlink = RTL_CONSTANT_STRING(L"\\??\\Quarantine");
	BOOLEAN SymlinkCreated = FALSE;
	g_pFilter = NULL;
	g_pQuarantineDirPath = NULL;


	do {

		// Init minifilter
		Status = InitMiniFilter(DriverObject, RegistryPath);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed to init minifilter (0x%X)", Status);
			break;
		}
		
		// Create device
		UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Quarantine");
		Status = IoCreateDevice(
			DriverObject,
			0,
			&DeviceName,
			FILE_DEVICE_UNKNOWN,
			0,
			FALSE,
			&DeviceObj);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed to create device (0x%X)", Status);
			break;
		}

		// Create symlink
		Status = IoCreateSymbolicLink(&Symlink, &DeviceName);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed to symboliclink (0x%X)", Status);
			break;
		}
		else {
			SymlinkCreated = TRUE;
		}

		g_pQuarantineDirPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH * sizeof(WCHAR) + sizeof(UNICODE_STRING), DRIVER_TAG);
		if (!g_pQuarantineDirPath)
		{
			Status = STATUS_MEMORY_NOT_ALLOCATED;
			LOG("Failed to allocate memory for quarantine dir");
			break;
		}

		RtlInitUnicodeString(g_pQuarantineDirPath, QuarantineDirPath);
		
		UNICODE_STRING PortName = RTL_CONSTANT_STRING(L"\\BackupPort");
		OBJECT_ATTRIBUTES PortNameObjectAttr;
		PSECURITY_DESCRIPTOR Sd;
		Status = FltBuildDefaultSecurityDescriptor(&Sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(Status)) {
			LOG("Fail creating SD for port");
			break;
		}

		InitializeObjectAttributes(&PortNameObjectAttr, &PortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, Sd);
		// Create the communication port
		Status = FltCreateCommunicationPort(
			g_pFilter,
			&g_pServerPort,
			&PortNameObjectAttr,
			NULL,
			ConnectNotifyCallback,
			DisconnectNotifyCallback,
			MessageNotifyCallback,
			1 // Max connections
		);

		if (!NT_SUCCESS(Status)) {
			LOG("Fail creating minifilter port");
			break;
		}

		// Start filtering
		Status = FltStartFiltering(g_pFilter);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed start filtering");
			break;
		}


	} while (false);

	if (!NT_SUCCESS(Status))
	{
		LOG("Error in DriverEntry: 0x%X", Status);

		if (g_pServerPort)
			FltCloseCommunicationPort(g_pServerPort);
		if (g_pFilter)
			FltUnregisterFilter(g_pFilter);
		if (SymlinkCreated)
			IoDeleteSymbolicLink(&Symlink);
		if (DeviceObj)
			IoDeleteDevice(DeviceObj);

		return Status;
	}

	// Add the relevant irp major functions
	DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

	g_pDriverObject = DriverObject;

	LOG("DriverEntry success");

	return Status;
}

VOID
DisconnectNotifyCallback(
	PVOID ConnectionCookie
)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	LOG("Enter");

	FltCloseClientPort(g_pFilter, &g_pClientPort);
	g_pClientPort = NULL;
}

NTSTATUS
ConnectNotifyCallback(
	PFLT_PORT ClientPort,
	PVOID ServerPortCookie,
	PVOID ConnectionContext,
	ULONG SizeOfContext,
	PVOID* ConnectionPortCookie
)
{
	UNREFERENCED_PARAMETER(ClientPort);
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);
	g_pClientPort = ClientPort;
	LOG("Enter");
	return NTSTATUS();
}

NTSTATUS
MessageNotifyCallback(
	PVOID PortCookie,
	PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	PULONG ReturnOutputLength
)
{
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferSize);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferSize);
	UNREFERENCED_PARAMETER(ReturnOutputLength);
	LOG("Enter");

	// Validate input buffer
	if (InputBuffer == NULL || InputBufferSize < sizeof(COMMAND_MESSAGE))
	{
		LOG("Input buffer is invalid (p: 0x%p, size: 0x%X)", InputBuffer, InputBufferSize);
		return STATUS_INVALID_PARAMETER;
	}

	PCOMMAND_MESSAGE Cmd = (PCOMMAND_MESSAGE)InputBuffer;
	NTSTATUS Status = STATUS_SUCCESS;

	*ReturnOutputLength = 0;

	switch (Cmd->Command)
	{
	case CMD_QUARANTINE:
	{
		// Essential kernel space prefix.
		WCHAR NtPrefix[] = L"\\??\\";

		// Construct the source path
		WCHAR SourcePath[MAX_PATH];
		RtlZeroMemory(SourcePath, sizeof(SourcePath));
		RtlCopyMemory(SourcePath, NtPrefix, wcslen(NtPrefix) * sizeof(WCHAR));
		RtlCopyMemory(SourcePath + wcslen(NtPrefix), Cmd->FilePath, wcslen(Cmd->FilePath)*sizeof(WCHAR));
		
		// Extract file name
		PWCHAR Filename = wcsrchr(SourcePath, L'\\');
		if (Filename == NULL)
		{
			LOG("File name cant be found in the file path: (%wZ)", SourcePath);
			return STATUS_INVALID_PARAMETER;
		}
		// Skip last backslash
		Filename ++; 
		
		// Construct the destination path
		WCHAR DestPath[MAX_PATH];
		RtlZeroMemory(DestPath, sizeof(DestPath));
		RtlCopyMemory(DestPath, NtPrefix, wcslen(NtPrefix) * sizeof(WCHAR));
		RtlCopyMemory(DestPath + wcslen(NtPrefix), QuarantineDirPath, wcslen(QuarantineDirPath) * sizeof(WCHAR));
		wcscat(DestPath, L"\\");
		wcscat(DestPath, Filename);

		// Open the source file
		HANDLE hFile;
		OBJECT_ATTRIBUTES SourceObjAttr;
		IO_STATUS_BLOCK IoStatus;
		UNICODE_STRING UniSourcePath;
		RtlInitUnicodeString(&UniSourcePath, SourcePath);
		InitializeObjectAttributes(&SourceObjAttr, &UniSourcePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		Status = ZwOpenFile(
			&hFile,
			DELETE | SYNCHRONIZE,
			&SourceObjAttr,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed to open the source file to quarantine: (0x%X) path: (%wZ)", Status, UniSourcePath);
			return Status;;
		}

		// Prepare FILE_NAME_INFORMATION for moving the file
		SIZE_T RenameInfoSize = sizeof(FILE_RENAME_INFORMATION) + (wcslen(DestPath)*sizeof(WCHAR));
		PFILE_RENAME_INFORMATION RenameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, RenameInfoSize, 'mner');
		if (RenameInfo == NULL)
		{
			ZwClose(hFile);
			LOG("Failed allocating memory for the FILE_RENAME_INFORMATION (0x%X)", Status);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(RenameInfo, RenameInfoSize);
		RenameInfo->ReplaceIfExists = TRUE;
		RenameInfo->RootDirectory = NULL;
		RenameInfo->FileNameLength = (ULONG)(wcslen(DestPath) * sizeof(WCHAR));
		RtlCopyMemory(RenameInfo->FileName, DestPath, RenameInfo->FileNameLength);

		Status = ZwSetInformationFile(
			hFile,
			&IoStatus,
			RenameInfo,
			(ULONG)RenameInfoSize,
			FileRenameInformation
		);

		ExFreePool(RenameInfo);
		ZwClose(hFile);

		if (!NT_SUCCESS(Status)) {
			LOG("Failed to move file to quarantine: 0x%X", Status);
			break;
		}

		// Create .orig file to store original path
		WCHAR OrigFilePath[MAX_PATH];
		RtlZeroMemory(OrigFilePath, MAX_PATH*sizeof(WCHAR));
		RtlCopyMemory(OrigFilePath, NtPrefix, wcslen(NtPrefix) * sizeof(WCHAR));
		RtlCopyMemory(OrigFilePath + wcslen(NtPrefix), QuarantineDirPath, wcslen(QuarantineDirPath) * sizeof(WCHAR));
		wcscat(OrigFilePath, L"\\");
		wcscat(OrigFilePath, Filename);
		wcscat(OrigFilePath, L".orig");

		UNICODE_STRING UniOrigPath;
		OBJECT_ATTRIBUTES OrigObjAttr;
		RtlInitUnicodeString(&UniOrigPath, OrigFilePath);
		InitializeObjectAttributes(&OrigObjAttr, &UniOrigPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hOrigFile;
		LARGE_INTEGER OrigFileSize;
		OrigFileSize.QuadPart = MAX_PATH * sizeof(WCHAR) * 2;
		Status = ZwCreateFile(
			&hOrigFile,
			GENERIC_WRITE | FILE_WRITE_DATA | SYNCHRONIZE,
			&OrigObjAttr,
			&IoStatus,
			&OrigFileSize,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_CREATE,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);

		if (NT_SUCCESS(Status)) {
			UNICODE_STRING UniSource;
			RtlInitUnicodeString(&UniSource, SourcePath);
			Status = ZwWriteFile(
				hOrigFile,
				NULL,
				NULL,
				NULL,
				&IoStatus,
				UniSource.Buffer,
				UniSource.Length,
				NULL,
				NULL
			);
			
			if (!NT_SUCCESS(Status)) {
				LOG("Failed to write original path to .orig file: 0x%X", Status);
			}
			
			ZwClose(hOrigFile);
		
		}
		else {
			LOG("Failed to create .orig file: 0x%X", Status);
		}

		break;
	}
	case CMD_RELEASE:
	{
		// Essential kernel space prefix.
		WCHAR NtPrefix[] = L"\\??\\";

		// Release a file: Move back to original path and delete .orig file
		WCHAR Filename[MAX_PATH];
		RtlZeroMemory(Filename, sizeof(Filename));
		RtlCopyMemory(Filename, Cmd->FilePath, wcslen(Cmd->FilePath) * sizeof(WCHAR));

		// Construct quarantined file path
		WCHAR QuarPath[MAX_PATH];
		RtlZeroMemory(QuarPath, sizeof(QuarPath));
		RtlCopyMemory(QuarPath, NtPrefix, wcslen(NtPrefix) * sizeof(WCHAR));
		RtlCopyMemory(QuarPath + wcslen(NtPrefix), QuarantineDirPath, wcslen(QuarantineDirPath) * sizeof(WCHAR));
		wcscat(QuarPath, L"\\");
		wcscat(QuarPath, Filename);

		// Construct .orig file path
		WCHAR OrigFilePath[MAX_PATH];
		RtlZeroMemory(OrigFilePath, sizeof(OrigFilePath));
		RtlCopyMemory(OrigFilePath, QuarPath, wcslen(QuarPath) * sizeof(WCHAR));
		wcscat(OrigFilePath, L".orig");

		// Read original path from .orig file
		HANDLE hOrigFile;
		OBJECT_ATTRIBUTES ObjAttr;
		IO_STATUS_BLOCK IoStatus;
		UNICODE_STRING UniOrigPath;
		RtlInitUnicodeString(&UniOrigPath, OrigFilePath);
		InitializeObjectAttributes(&ObjAttr, &UniOrigPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		// Open origin file
		Status = ZwOpenFile(
			&hOrigFile,
			DELETE | SYNCHRONIZE,
			&ObjAttr,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(Status)) {
			LOG("Failed to open .orig file for reading: 0x%X", Status);
			break;
		}

		// Read its content which is the source file path
		WCHAR OriginalPath[MAX_PATH];
		Status = ZwReadFile(
			hOrigFile,
			NULL,
			NULL,
			NULL,
			&IoStatus,
			OriginalPath,
			MAX_PATH*sizeof(WCHAR),
			NULL,
			NULL
		);
		ZwClose(hOrigFile);
		if (!NT_SUCCESS(Status)) {
			LOG("Failed to read original path: 0x%X", Status);
			break;
		}

		// Put null terminate
		OriginalPath[IoStatus.Information / sizeof(WCHAR)] = L'\0';

		// Open the quarantined file for moving
		HANDLE hFile;
		UNICODE_STRING UniQuarPath;
		RtlInitUnicodeString(&UniQuarPath, QuarPath);
		InitializeObjectAttributes(&ObjAttr, &UniQuarPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		Status = ZwOpenFile(
			&hFile,
			DELETE | SYNCHRONIZE,
			&ObjAttr,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT
		);
		if (!NT_SUCCESS(Status)) {
			LOG("Failed to open quarantined file for release: 0x%X", Status);
			break;
		}

		// Prepare FILE_RENAME_INFORMATION
		size_t RenameInfoSize = sizeof(FILE_RENAME_INFORMATION) + wcslen(OriginalPath) * sizeof(WCHAR);
		PFILE_RENAME_INFORMATION RenameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, RenameInfoSize, 'mner');
		if (RenameInfo == NULL) {
			ZwClose(hFile);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		RtlZeroMemory(RenameInfo, RenameInfoSize);
		RenameInfo->ReplaceIfExists = TRUE;
		RenameInfo->RootDirectory = NULL;
		RenameInfo->FileNameLength = (ULONG)wcslen(OriginalPath) * sizeof(WCHAR);
		RtlCopyMemory(RenameInfo->FileName, OriginalPath, RenameInfo->FileNameLength);

		// Set file information
		Status = ZwSetInformationFile(
			hFile,
			&IoStatus,
			RenameInfo,
			(ULONG)RenameInfoSize,
			FileRenameInformation
		);

		ExFreePool(RenameInfo);
		ZwClose(hFile);

		if (!NT_SUCCESS(Status)) {
			LOG("Failed to move file back to original path: 0x%X", Status);
			break;
		}

		InitializeObjectAttributes(&ObjAttr, &UniOrigPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

		// Delete the .orig file
		HANDLE hOrigToDelete;
		Status = ZwOpenFile(
			&hOrigToDelete,
			DELETE | SYNCHRONIZE,
			&ObjAttr,
			&IoStatus,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT
		);

		if (NT_SUCCESS(Status)) {
			FILE_DISPOSITION_INFORMATION DispInfo;
			DispInfo.DeleteFile = TRUE;
			Status = ZwSetInformationFile(
				hOrigToDelete,
				&IoStatus,
				&DispInfo,
				sizeof(DispInfo),
				FileDispositionInformation
			);
			ZwClose(hOrigToDelete);
			if (!NT_SUCCESS(Status)) {
				LOG("Failed to delete .orig file: 0x%X", Status);
			}
		}
		break;
	}
	case CMD_LIST:
	{
		break;
	}
	default:
		LOG("Invalid command: (0x%X)", Cmd->Command);
		return STATUS_INVALID_PARAMETER;
	}


	return Status;
}

NTSTATUS
OnCreateClose(
	_In_ PDEVICE_OBJECT,
	_In_ PIRP Irp
)
{
	LOG("Enter");
	return CompleteRequest(Irp);
}

NTSTATUS
OnDeviceControl(
	_In_ PDEVICE_OBJECT,
	_In_ PIRP Irp
)
{
	LOG("Enter");
	// TODO Handle commands from agent for quarantine
	return CompleteRequest(Irp);
}

NTSTATUS
InitMiniFilter(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING RegistryPath
)
{
	HANDLE hKey = NULL;
	HANDLE hSubKey = NULL;
	NTSTATUS Status = STATUS_SUCCESS;

	LOG("Initializing the minifilter");

	do {

		// Add registry data for minifilter registration

		// Open key for write
		OBJECT_ATTRIBUTES KeyAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(RegistryPath, OBJ_KERNEL_HANDLE);
		Status = ZwOpenKey(
			&hKey,
			KEY_WRITE,
			&KeyAttr);
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwOpenKey::Failed open key (0x%X)", Status);
			break;
		}

		// Create the subkey and key
		UNICODE_STRING SubKey = RTL_CONSTANT_STRING(L"Instances");
		OBJECT_ATTRIBUTES SubKeyAttr;
		InitializeObjectAttributes(
			&SubKeyAttr,
			&SubKey, 
			OBJ_KERNEL_HANDLE, 
			hKey, 
			NULL);
		Status = ZwCreateKey(
			&hSubKey,
			KEY_WRITE,
			&SubKeyAttr,
			0,
			NULL,
			0,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwCreateKey::Failed open subkey (0x%X)", Status);
			break;
		}

		// Set the default instance value
		UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"DefaultInstance");
		WCHAR Name[] = L"QuarantineMfltDefaultInstance";
		Status = ZwSetValueKey(
			hSubKey,
			&ValueName,
			0,
			REG_SZ,
			Name,
			sizeof(Name));
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwSetValueKey::Failed setting default instance name (0x%X)", Status);
			break;
		}

		// Create "instance" key under "Instances"
		UNICODE_STRING InstKeyName;
		RtlInitUnicodeString(&InstKeyName, Name);
		HANDLE hInstKey;
		InitializeObjectAttributes(
			&SubKeyAttr,
			&InstKeyName,
			OBJ_KERNEL_HANDLE,
			hSubKey,
			NULL);
		Status = ZwCreateKey(
			&hInstKey,
			KEY_WRITE,
			&SubKeyAttr,
			0,
			NULL,
			0,
			NULL
		);
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwCreateKey::Failed creating instance key (0x%X)", Status);
			break;
		}

		// Write altitude
		WCHAR Altitude[] = L"409898";
		UNICODE_STRING AltitudeName = RTL_CONSTANT_STRING(L"Altitude");
		Status = ZwSetValueKey(
			hInstKey,
			&AltitudeName,
			0,
			REG_SZ,
			Altitude,
			sizeof(Altitude));
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwSetValueKey::Failed writing altitude (0x%X)", Status);
			break;
		}

		// Write flags
		UNICODE_STRING FlagName = RTL_CONSTANT_STRING(L"Flags");
		ULONG Flags = 0;
		Status = ZwSetValueKey(
			hInstKey,
			&FlagName,
			0,
			REG_DWORD,
			&Flags,
			sizeof(Flags));
		if (!NT_SUCCESS(Status))
		{
			LOG("ZwSetValueKey::Failed writing flags (0x%X)", Status);
			break;
		}

		ZwClose(hInstKey);

		// Construct the callbacks array
		FLT_OPERATION_REGISTRATION CONST Callbacks[] =
		{
			{IRP_MJ_DIRECTORY_CONTROL, 0, OnPreDirectoryControl, OnPostDirectoryControl},
			{ IRP_MJ_CREATE, 0, OnPreCreateFile, NULL },
			{IRP_MJ_OPERATION_END}
		};

		// Construct the registration struct
		FLT_REGISTRATION CONST Reg =
		{
			sizeof(FLT_REGISTRATION),
			FLT_REGISTRATION_VERSION,
			0,										// Flags
			NULL,									// Context
			Callbacks,								// Operation callbacks
			QuarantineUnload,						// Unload
			QuarantineInstanceSetup,				// Instance setup
			QuarantineInstanceQueryTeardown,		// Instance query teardown
			QuarantineInstanceTeardownStart,		// Instance teardown start
			QuarantineInstanceTeardownComplete,		// Instance teardown complete
		};

		Status = FltRegisterFilter(pDriverObject, &Reg, &g_pFilter);
		if (!NT_SUCCESS(Status))
		{
			LOG("FltRegisterFilter::Failed FltRegisterFilter (0x%X)", Status);
			break;
		}

	} while (false);

	// If subkey not NULL
	if (hSubKey)
	{
		// If we failed in the process
		if (!NT_SUCCESS(Status))
		{
			ZwDeleteKey(hSubKey);
		}
	}

	// If key is not null
	if (hKey)
	{
		ZwClose(hKey);
	}

	return Status;
}

NTSTATUS
QuarantineUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	LOG("Unloading quarantine filter");
	if (g_pServerPort)
		FltCloseCommunicationPort(g_pServerPort);
	FltUnregisterFilter(g_pFilter);
	UNICODE_STRING Symlink = RTL_CONSTANT_STRING(L"\\??\\Quarantine");
	IoDeleteSymbolicLink(&Symlink);
	IoDeleteDevice(g_pDriverObject->DeviceObject);
	ExFreePool(g_pQuarantineDirPath);
	return STATUS_SUCCESS;
}

NTSTATUS
QuarantineInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);

	LOG("Enter");

	NTSTATUS Status = STATUS_SUCCESS;

	if (VolumeFilesystemType != FLT_FSTYPE_NTFS)
		Status = STATUS_FLT_DO_NOT_ATTACH;

	return Status;
}

NTSTATUS
QuarantineInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	LOG("Enter");

	return STATUS_SUCCESS;
}

VOID
QuarantineInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	LOG("Enter");
}

VOID
QuarantineInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	LOG("Enter");
}

// intercept IO request to directly open the directory
FLT_PREOP_CALLBACK_STATUS OnPreCreateFile(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	FLT_PREOP_CALLBACK_STATUS Status = FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->RequestorMode == KernelMode)
		return Status;

	auto const& Params = Data->Iopb->Parameters.Create;

	if (!(Params.Options & FILE_DIRECTORY_FILE || Params.Options & FILE_DELETE_ON_CLOSE))
		return Status;

	// Its an attempt to interact with a file we should
	// check if its our directory
	// We want to receive the DOS path of the directory
	// to compare with the parent directory of our quarantine dir
	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	POBJECT_NAME_INFORMATION ObjectNameInformation;

	// Get the device in DOS format
	IoQueryFileDosDeviceName(FltObjects->FileObject, &ObjectNameInformation);
	// Get the full file name out of the IO data (without the device name)
	NTSTATUS NtStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &FileNameInfo);

	// If success we can combine the names and compare with our directory
	if (NT_SUCCESS(NtStatus) && ObjectNameInformation)
	{
		UNICODE_STRING DeviceLessPath = FltObjects->FileObject->FileName;
		UNICODE_STRING DeviceDOS = ObjectNameInformation->Name;

		USHORT Length = DeviceLessPath.Length + DeviceDOS.Length;
		PWCHAR Buffer = NULL;

		Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, Length);
		if (Buffer == NULL)
		{
			LOG("Failed to allocate memory for the path buffer");
			goto exit;
		}

		UNICODE_STRING FullDOSFilename;
		
		// Copy full dos path
		FullDOSFilename.Length = Length;
		FullDOSFilename.Buffer = Buffer;
		RtlCopyMemory(FullDOSFilename.Buffer, DeviceDOS.Buffer, DeviceDOS.Length);
		RtlCopyMemory(FullDOSFilename.Buffer + (DeviceDOS.Length / sizeof(WCHAR)), DeviceLessPath.Buffer, DeviceLessPath.Length);

		if (RtlEqualUnicodeString(&FullDOSFilename, g_pQuarantineDirPath, TRUE))
		{
			// There is a match, we should intercept this operation
			// Any one should think this directory dose not exists
			LOG("Prevented interaction with %wZ", FullDOSFilename);
			Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
			Status = FLT_PREOP_COMPLETE;
		}
		
		ExFreePool(Buffer);
	}

	
exit:
	if(NT_SUCCESS(NtStatus))
		FltReleaseFileNameInformation(FileNameInfo);
	if(ObjectNameInformation)
		ExFreePool(ObjectNameInformation);


	return Status;
}


// On the PostDirectoryControl we can catch
// i/o requests to see the content of the **folder that contains**
// our quarantine folder and the hide our folder from the response
// so the end requester wont know this dir exists
FLT_POSTOP_CALLBACK_STATUS
OnPostDirectoryControl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	if (Data->RequestorMode == KernelMode ||
		Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ||
		(Flags & FLTFL_POST_OPERATION_DRAINING) //this post-operation
		//  routine has been called for cleanup processing (drained).  Since this
		//  instance is going away, you should perform a minimum of operations
		//  while processing this completion.
		)
		return FLT_POSTOP_FINISHED_PROCESSING;

	auto& Params = Data->Iopb->Parameters.DirectoryControl.QueryDirectory;

	if (FltObjects->FileObject->FileName.Length <= 0)
	{
		LOG("The file name length is >=0  so its possible a TAB completion");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	static CONST FILE_INFORMATION_DEFINITION Definitions[] =
	{
			FileFullDirectoryInformationDefinition,
			FileBothDirectoryInformationDefinition,
			FileDirectoryInformationDefinition,
			FileNamesInformationDefinition,
			FileIdFullDirectoryInformationDefinition,
			FileIdBothDirectoryInformationDefinition,
			FileIdExtdDirectoryInformationDefinition,
			FileIdGlobalTxDirectoryInformationDefinition
	};

	BOOLEAN FoundMatch = FALSE;
	const FILE_INFORMATION_DEFINITION* pFID = NULL;
	for (ULONG Index = 0; Index < sizeof(Definitions); Index++)
	{
		if (Definitions[Index].Class == Params.FileInformationClass)
		{
			pFID = &Definitions[Index];
			FoundMatch = TRUE;
		}
	}

	if (!FoundMatch)
	{
		LOG("No match for info class wont operate on the I/O request.");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// We want to receive the DOS path of the directory
	// to compare with the parent directory of our quarantine dir
	POBJECT_NAME_INFORMATION pDosPath = NULL;
	IoQueryFileDosDeviceName(FltObjects->FileObject, &pDosPath);
	if (pDosPath)
	{
		PUCHAR Base = NULL;
		
		// If MDL is available we should use it to retrieve the path
		if (Params.MdlAddress)
			Base = (PUCHAR)MmGetSystemAddressForMdlSafe(Params.MdlAddress, NormalPagePriority);

		// If no MDL available we should get the path from the buffer
		if (!Base)
			Base = (PUCHAR)Params.DirectoryBuffer;

		// If Base is still NULL we cant compare and we should finish
		if (Base == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Find the last backslash
		PWCHAR LastBackSlash = wcsrchr(g_pQuarantineDirPath->Buffer, L'\\');
		
		UNICODE_STRING ParentDir;
		ParentDir.Buffer = g_pQuarantineDirPath->Buffer;

		// Calculate the length of the full parent directory path
		ParentDir.Length = USHORT(LastBackSlash - g_pQuarantineDirPath->Buffer) * sizeof(WCHAR);

		if (RtlEqualUnicodeString(&ParentDir, &pDosPath->Name, TRUE))
		{
			// We got an IO request that will reveal our hidden quarantine directory
			// We should hide it
			ULONG NextOffset = 0;
			PUCHAR Prev = NULL;
			PWCHAR QuarantineDirName = LastBackSlash + 1;

			do {

				// Bug in Windows macro in which FILE_INFORMATION_DEFINITION
				// File name points to length and vice versa
				ULONG FileNameLength = *(PULONG)(Base + pFID->FileNameLengthOffset);
				PCWSTR FileName = (PCWSTR)(Base + pFID->FileNameOffset);

				if (FileNameLength == 0)
				{
					// If filename length is 0 this entry is result of Tab completion and we should just skeep this try
					ExFreePool(pDosPath);
					Data->IoStatus.Status = STATUS_NOT_FOUND;
					Data->IoStatus.Information = 0;
					return FLT_POSTOP_FINISHED_PROCESSING;
				}

				// Get pointer to the next entry
				NextOffset = *(PULONG)(Base + pFID->NextEntryOffset);


				UNICODE_STRING FileNameDebug;
				RtlInitUnicodeString(&FileNameDebug, FileName);

				// If the current entry is our directory we want to hide it form the list
				if (FileNameLength && _wcsnicmp(QuarantineDirName, FileName, FileNameLength / sizeof(WCHAR)) == 0)
				{
					LOG("Found our directory, hiding it");
					//First entry, just move the buffer pointer to the next entry
					if (Prev == NULL)
					{
						Params.DirectoryBuffer = Base + NextOffset;
						FltSetCallbackDataDirty(Data);
					}
					else {
						// Not the first entry, we should just update the prev entry to point
						// to the current next entry
						if (NextOffset == 0)
						{
							// The entry is the last one we should SET the prev nextEntry to 0
							*(PULONG)(Prev + pFID->NextEntryOffset) = 0;
						}
						else {
							*(PULONG)(Prev + pFID->NextEntryOffset) += NextOffset;

						}
					}
					break;
				}

				Prev = Base;
				Base += NextOffset;

			} while (NextOffset != 0); // When NextOffset it means it is the last entry
		}

	ExFreePool(pDosPath);
	}
	else {
		LOG("Could not convert to DOS path: '%wZ'", FltObjects->FileObject->FileName);
	}
	
	return FLT_POSTOP_FINISHED_PROCESSING;
}

// If the I/O request is associating
// With our quarantine directory
// We want to deny this request
FLT_PREOP_CALLBACK_STATUS
OnPreDirectoryControl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	if (Data->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	POBJECT_NAME_INFORMATION NameInfo;
	if (!NT_SUCCESS(IoQueryFileDosDeviceName(FltObjects->FileObject, &NameInfo)))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	
	// Test if querying the quarantine directory
	FLT_PREOP_CALLBACK_STATUS Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	UNICODE_STRING DosPath = NameInfo->Name;
	if (RtlEqualUnicodeString(&DosPath, g_pQuarantineDirPath, TRUE))
	{
		// Found out that this is an IO req on the quarantine folder
		LOG("Blocking IO request on the our directory: ('%wZ')", DosPath);
		Data->IoStatus.Status = STATUS_NOT_FOUND;
		Data->IoStatus.Information = 0;
		Status = FLT_PREOP_COMPLETE;
	}

	ExFreePool(NameInfo);
	return Status;
}