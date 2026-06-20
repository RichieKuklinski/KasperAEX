#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

UNICODE_STRING symLinkName;
#define PUTIN_SHIELD_DEVICE_TYPE 0x8001

#define IOCTL_PUTIN_SHIELD_START_PROTECTION \
    CTL_CODE(PUTIN_SHIELD_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PUTIN_SHIELD_STOP_PROTECTION \
       CTL_CODE(PUTIN_SHIELD_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
// ==============================================

VOID ProcessCreateNotifyRoutine(
    IN HANDLE ParentId,
    IN HANDLE ProcessId,
    IN BOOLEAN Create
);

VOID PutinAgainstExploits(HANDLE ParentId, HANDLE ProcessId);
VOID PutinHandleProcessStop(HANDLE ProcessId);
