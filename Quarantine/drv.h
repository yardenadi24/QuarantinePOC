#pragma once
#include <ntifs.h>
#include <fltKernel.h> // Need to add to the linker: fltmgr.lib
#include "Utils.h"

#pragma warning(disable: 4995)
#pragma warning(disable: 4996)

#define DRIVER_TAG 'tnrQ'
#define DRIVER_PREFIX "QuarantineDrv: "

#define LOG(s, ...) DbgPrint(DRIVER_PREFIX "%s::" s "\n",__FUNCTION__,__VA_ARGS__)

#define MAX_PATH 256
#define QuarantineDirPath L"C:\\EdrPOC\\Quarantine"

// Declarations

NTSTATUS
CompleteRequest(
	PIRP Irp,
	NTSTATUS Status = STATUS_SUCCESS, // Default status for IRP
	ULONG_PTR Info = 0				  // Default info which is used for (written usually)
);				  

NTSTATUS
OnCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS
OnDeviceControl(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
);

NTSTATUS
InitMiniFilter(
	PDRIVER_OBJECT  pDriverObject,
	PUNICODE_STRING RegistryPath
);

NTSTATUS
QuarantineUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
QuarantineInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
QuarantineInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

VOID
QuarantineInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
QuarantineInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
OnPostDirectoryControl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID,
	FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
OnPreDirectoryControl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*
);

FLT_PREOP_CALLBACK_STATUS OnPreCreateFile(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID*
);