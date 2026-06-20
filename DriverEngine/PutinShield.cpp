#include "PutinShieldTemplate.h"
LARGE_INTEGER g_CallbackRegistrationCookie;

typedef struct _PROCESS_TOKEN_ENTRY {
	LIST_ENTRY ListEntry;    
	HANDLE ProcessId;       
	PACCESS_TOKEN OrigToken;  
} PROCESS_TOKEN_ENTRY, * PPROCESS_TOKEN_ENTRY;

LIST_ENTRY TargetProcessListHead;
FAST_MUTEX ProcessListMutex;


// =================================================================

VOID ThreadNotifyRoutine(_In_ HANDLE ProcessId, _In_ HANDLE ThreadId, _In_ BOOLEAN Create)
{
	if (Create)
	{
		PEPROCESS EPROCESS = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &EPROCESS)))
		{
			PACCESS_TOKEN threadStartToken = PsReferencePrimaryToken(EPROCESS);
			if (threadStartToken != NULL)
			{
				ExAcquireFastMutex(&ProcessListMutex);

				PLIST_ENTRY link = TargetProcessListHead.Flink;
				while (link != &TargetProcessListHead)
				{
					PPROCESS_TOKEN_ENTRY entry = CONTAINING_RECORD(link, PROCESS_TOKEN_ENTRY, ListEntry);

					if (entry->ProcessId == ProcessId)
					{
						if (entry->OrigToken != threadStartToken)
						{
							KdPrint(("thread stealing detected %p\n", ProcessId, entry->OrigToken, threadStartToken));

						}
						break;
					}
					link = link->Flink;
				}

				ExReleaseFastMutex(&ProcessListMutex);
				PsDereferencePrimaryToken(threadStartToken);
			}
			ObDereferenceObject(EPROCESS);
		}
	}
	else
	{
		KdPrint(("thread disable ID: %p in process ID: %p\n", ThreadId, ProcessId));
	}
}

// =================================================================
void ANTI_TOKEN_GET_EXPLOIT(HANDLE ParentId, HANDLE ProcessId)
{
	UNREFERENCED_PARAMETER(ParentId);

	PEPROCESS EPROCESS = NULL;
	NTSTATUS EPROCESS_FUNC = PsLookupProcessByProcessId(ProcessId, &EPROCESS);

	if (NT_SUCCESS(EPROCESS_FUNC))
	{
		PACCESS_TOKEN savetoken = PsReferencePrimaryToken(EPROCESS);
		if (savetoken != NULL)
		{
			PPROCESS_TOKEN_ENTRY entry = (PPROCESS_TOKEN_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_TOKEN_ENTRY), 'shld');

			if (entry != NULL)
			{
				entry->ProcessId = ProcessId;
				entry->OrigToken = savetoken;

				ExAcquireFastMutex(&ProcessListMutex);
				InsertTailList(&TargetProcessListHead, &entry->ListEntry);
				ExReleaseFastMutex(&ProcessListMutex);

				KdPrint(("processe %p token saved: %p\n", ProcessId, savetoken));
			}
			else
			{
				PsDereferencePrimaryToken(savetoken);
			}
		}
		ObDereferenceObject(EPROCESS);
	}
}
// =================================================================

// =================================================================
VOID ProcessCreateNotifyRoutineEx(IN OUT PEPROCESS Process, IN HANDLE ProcessId, IN OUT PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	if (CreateInfo != NULL)
	{
		ANTI_TOKEN_GET_EXPLOIT(CreateInfo->ParentProcessId, ProcessId);

	}
	else
	{
		// Åñëè CreateInfo == NULL, çíà÷èò ïðîöåññ ÇÀÂÅÐØÀÅÒÑß
		PutinHandleProcessStop(ProcessId);
	}
}

//NTSTATUS REESTERSCALLBACK(
//	_In_ PVOID CallbackContext,
//	_In_opt_ PVOID Argument1,
//	_In_opt_ PVOID Argument2
//)
//{
//
//	return STATUS_SUCCESS;
//}

void PutinHandleProcessStop(HANDLE ProcessId)
{
	ExAcquireFastMutex(&ProcessListMutex);

	PLIST_ENTRY link = TargetProcessListHead.Flink;
	while (link != &TargetProcessListHead)
	{
		PPROCESS_TOKEN_ENTRY entry = CONTAINING_RECORD(link, PROCESS_TOKEN_ENTRY, ListEntry);

		if (entry->ProcessId == ProcessId)
		{
			RemoveEntryList(link);
			PsDereferencePrimaryToken(entry->OrigToken);
			ExFreePoolWithTag(entry, 'shld');

			KdPrint(("process %p stopped...\n", ProcessId));
			break;
		}
		link = link->Flink;
	}
	ExReleaseFastMutex(&ProcessListMutex);
}

void PutinDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyRoutineEx, TRUE);
	PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);

	ExAcquireFastMutex(&ProcessListMutex);
	while (!IsListEmpty(&TargetProcessListHead))
	{
		PLIST_ENTRY link = RemoveHeadList(&TargetProcessListHead);
		PPROCESS_TOKEN_ENTRY entry = CONTAINING_RECORD(link, PROCESS_TOKEN_ENTRY, ListEntry);

		if (entry->OrigToken != NULL) 
		{
			PsDereferencePrimaryToken(entry->OrigToken);
		}

		ExFreePoolWithTag(entry, 'shld');
	}
	ExReleaseFastMutex(&ProcessListMutex);

	IoDeleteSymbolicLink(&symLinkName);

	if (DriverObject->DeviceObject != nullptr)
	{
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	KdPrint(("driver unload\n"));
}


NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	ULONG ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;

	switch (ioControlCode)
	{
	case IOCTL_PUTIN_SHIELD_START_PROTECTION:

		break;

	case IOCTL_PUTIN_SHIELD_STOP_PROTECTION:

		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS IRPCREATECLOSE(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = PutinDriverUnload;
	KdPrint(("PutinShield.sys load...\n"));
	
	UNICODE_STRING deviceName;
	PDEVICE_OBJECT deviceObject = nullptr;

	RtlInitUnicodeString(&deviceName, L"\\Device\\PutinShield");

	NTSTATUS Device = IoCreateDevice(
		DriverObject,             
		sizeof(ULONG),            
		&deviceName,              
		FILE_DEVICE_UNKNOWN,      
		0,                         
		FALSE,                     
		&deviceObject              
	);

	if (!NT_SUCCESS(Device))
	{
		return Device;
	}
	RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\PutinShieldLink");
	NTSTATUS symbol = IoCreateSymbolicLink(&symLinkName, &deviceName);

	if (!NT_SUCCESS(symbol))
	{
		IoDeleteDevice(deviceObject);
		return symbol;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = IRPCREATECLOSE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IRPCREATECLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	InitializeListHead(&TargetProcessListHead);
	ExInitializeFastMutex(&ProcessListMutex);

	NTSTATUS PUTIN_REGISTER_CALLBACK = PsSetCreateProcessNotifyRoutineEx(ProcessCreateNotifyRoutineEx, FALSE);
	NTSTATUS PUTIN_REGISTER_CALLBACK_FOR_THREAD = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"320000");
	// NTSTATUS status = CmRegisterCallbackEx(RegistryCallback, &altitude, DriverObject, NULL, &g_CallbackRegistrationCookie, NULL);

	if (NT_SUCCESS(PUTIN_REGISTER_CALLBACK) && NT_SUCCESS(PUTIN_REGISTER_CALLBACK_FOR_THREAD))
	{
		KdPrint(("PutinShield initialize callbacks success\n"));
	}
	else
	{
		KdPrint(("PutinShield initialize callback error\n"));
	}
	return STATUS_SUCCESS;
}