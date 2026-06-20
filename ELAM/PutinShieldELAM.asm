FORMAT PE64 NATIVE
; точка входа драйвера DriverEntry не сказал бы, что интересная для того, кто изучает сурсы этого антивируса
; желательно начать с функции MAIN_REGISRTER_ELAM_CALLBACK в которй непосредственно происходит регистрация каллбека
; ELAM-драйвер устроен так, что он запускается самым первым и может анализировать другие драйвера(уязвимые)

; проверка драйвера на 2 этапа:
; 1. по хэшу. сверяется хэш уязвимого драйвера с тем, что проверяется(sha-256/sha-1), можно использовать функции из cng, но я решил, что буду вручную
; 2. по имени драйвера. сверять имя проверяемого драйвера с именем драйвера который находится в черном списке, условно на том же loldrviers
; подробнее про ELAM-драйвер вы можете почитать мою статью - https://yougame.biz/threads/380857/

ENTRY DriverEntry
include 'blacklist.inc'

SECTION '.text' CODE READABLE EXECUTABLE
DriverEntry:
    SUB    RSP, 50H
    MOV    [RSP + 40H], RCX
    MOV    [RSP + 48H], RDX

    MOV    RAX, CreateCloseHandler
    MOV    [RCX + 70H], RAX
    MOV    [RCX + 80H], RAX

    MOV    RAX, IoControlHandler
    MOV    [RCX + 0E0H], RAX

    MOV    RAX, DriverUnload
    MOV    [RCX + 68H], RAX

    MOV    RCX, [RSP + 40H]
    XOR    EDX, EDX
    LEA    R8, [DevName]
    MOV    R9D, 22H
    MOV    QWORD [RSP + 20H], 0
    MOV    BYTE [RSP + 28H], 0
    LEA    RAX, [pDeviceObject]
    MOV    QWORD [RSP + 30H], RAX
    CALL    QWORD [IoCreateDevice]

    TEST    EAX, EAX
    JS    @F

    LEA    RCX, [SymName]
    LEA    RDX, [DevName]
    CALL    QWORD [IoCreateSymbolicLink]

    TEST    EAX, EAX
    JS    .err_dev

    MOV    RAX, [pDeviceObject]
    AND    DWORD [RAX + 1CH], NOT 80H

    CALL    MAIN_REGISRTER_ELAM_CALLBACK

    XOR    EAX, EAX
    ADD    RSP, 50H
    RET

.err_dev:
    MOV    RCX, [pDeviceObject]
    CALL    QWORD [IoDeleteDevice]
@@:
    MOV    EAX, 0C0000001H
    ADD    RSP, 50H
    RET

CreateCloseHandler:
    SUB    RSP, 28H
    XOR    EAX, EAX
    MOV    [RDX + 30H], EAX
    MOV    QWORD [RDX + 38H], 0
    MOV    RCX, RDX
    XOR    EDX, EDX
    CALL    QWORD [IoCompleteRequest]
    XOR    EAX, EAX
    ADD    RSP, 28H
    RET

IoControlHandler:
    SUB    RSP, 28H
    MOV    RCX, RDX
    MOV    [RSP + 30H], RDX
    CALL    QWORD [IoGetCurrentIrpStackLocation]

    MOV    EAX, [RAX + 08H]
    CMP    EAX, IOCTL_AV_COMMAND
    JNE    .err_ioctl

    MOV    RCX, [RSP + 30H]
    MOV    RAX, [RCX + 18H]

    MOV    RCX, [RSP + 30H]
    XOR    EAX, EAX
    MOV    [RCX + 30H], EAX
    MOV    QWORD [RCX + 38H], 4
    JMP    .complete

.err_ioctl:
    MOV    RCX, [RSP + 30H]
    MOV    EAX, 0C00000BBH
    MOV    [RCX + 30H], EAX
    MOV    QWORD [RCX + 38H], 0

.complete:
    XOR    EDX, EDX
    CALL    QWORD [IoCompleteRequest]
    XOR    EAX, EAX
    ADD    RSP, 28H
    RET

MAIN_REGISRTER_ELAM_CALLBACK:
    SUB    RSP, 28H
    LEA    RCX, [BootDriverCallbackRountine]
    XOR    EDX, EDX
    CALL    QWORD [IoRegisterBootDriverCallback]
    MOV    [ElamCallbackHandle], RAX
    ADD    RSP, 28H
    RET

UNREGITSER_ELAM_CALLBACK:
    SUB    RSP, 28H
    MOV    RCX, [ElamCallbackHandle]
    TEST    RCX, RCX
    JZ    @F
    CALL    QWORD [IoUnregisterBootDriverCallback]
@@:
    ADD    RSP, 28H
    RET


BootDriverCallbackRountine:
    SUB    RSP, 48H

    MOV [RSP + 20h], RCX
    MOV [RSP + 28h], RDX
    MOV [RSP + 30h], R8

    CMP    EDX, BdCbInitializeImage
    JNE    .exit
    MOV [RSP + 30H], R8

    MOV RSI, DRIVER_BLACK_LIST
    MOV ECX, DRIVER_BLACK_LIST_COUNT ; проверка по черному списку драйверов(имя сверяется с блек-листом)
.@@:
    MOV RDX, [RSI]

    PUSH RCX
    PUSH RSI

    LEA RCX, [R8 + 08h]
    MOV R8D, 1
    CALL [RtlEqualUnicodeString]

    POP RSI
    POP RCX

    TEST AL, AL
    JNZ .DRIVER_BLOCK

    ADD RSI, 8
    DEC ECX
    JNZ @b

   ; ========================================

    MOV R8, [RSP + 20H]
    MOV RCX, [R8 + 38H]
    LEA RDX, [CertHash]
    MOV R8D, SHA256_HASH_SIZE
    XOR R9D, R9D
    CALL    QWORD [IoGetImageCertificateInfo]

    TEST EAX, EAX
    JS .DRIVER_BLOCK

    LEA RCX, [CertHash]
    LEA RDX, [CERT_BLACK_LIST]
    MOV R8D, CERT_BLACK_LIST_COUNT
    CALL CompareCertHashInList

    TEST AL, AL
    JNZ .DRIVER_BLOCK

.DRIVER_SUCESS:
    XOR EAX, EAX
    ADD RSP, 48H
    RET

.DRIVER_BLOCK:
    MOV EAX, STATUS_ACESS_DENIED
    ADD RSP, 40H
    RET
.exit:
    ADD    RSP, 40H
    RET

CompareCertHashInList: ; проверка хэшу
    SUB   RSP, 28H
    MOV   R9, RCX
    XOR   EAX, EAX
    TEST  R8D, R8D
    JZ    .ret

@@:
    MOV   R10, QWORD [R9]
    CMP   R10, QWORD [RDX]
    JNE   @F
    MOV   R10, QWORD [R9+8]
    CMP   R10, QWORD [RDX+8]
    JNE   @F
    MOV   R10, QWORD [R9+16]
    CMP   R10, QWORD [RDX+16]
    JNE   @F
    MOV   R10, QWORD [R9+24]
    CMP   R10, QWORD [RDX+24]
    JNE   @F
    MOV   EAX, 1
    JMP   .ret

@@:
    ADD   RDX, 32
    DEC   R8D
    JNZ   @B

.ret:
    ADD   RSP, 28H
    RET

DriverUnload:
    SUB    RSP, 40H
    CALL UNREGITSER_ELAM_CALLBACK
    LEA    RCX, [SymName]
    CALL QWORD [IoDeleteSymbolicLink]
    MOV    RAX, [pDeviceObject]
    TEST RAX, RAX
    JZ    @F
    MOV    RCX, RAX
    CALL    QWORD [IoDeleteDevice]
@@:
    ADD    RSP, 40H
    RET

SECTION '.data' DATA READABLE WRITEABLE

pDeviceObject DQ 0
ElamCallbackHandle    DQ 0
align 16
CertHash db 32 dup(0)
DevName:
    DW .str_end - .str
    DW .str_end - .str + 2
    DD 0
    DQ .str
.str:
    DU '\Device\YouGameDevice'
    DW 0
.str_end:

SymName:
    DW .str_end - .str
    DW .str_end - .str + 2
    DD 0
    DQ .str
.str:
    DU '\DosDevices\YouGame'
    DW 0
.str_end:

section '.idata' import data readable writeable
  dd 0, 0, 0, RVA ntoskrnl_name, RVA ntoskrnl_table
  dd 0, 0, 0, 0, 0

  ntoskrnl_table:
    IoCreateDevice            DQ RVA _IoCreateDevice
    IoDeleteDevice            DQ RVA _IoDeleteDevice
    IoCreateSymbolicLink        DQ RVA _IoCreateSymbolicLink
    IoDeleteSymbolicLink        DQ RVA _IoDeleteSymbolicLink
    IoCompleteRequest        DQ RVA _IoCompleteRequest
    IoGetCurrentIrpStackLocation    DQ RVA _IoGetCurrentIrpStackLocation
    IoRegisterBootDriverCallback    DQ RVA _IoRegisterBootDriverCallback
    IoUnregisterBootDriverCallback    DQ RVA _IoUnregisterBootDriverCallback
    RtlEqualUnicodeString        DQ RVA _RtlEqualUnicodeString
    IoGetImageCertificateInfo    DQ RVA _IoGetImageCertificateInfo
    DQ 0

  ntoskrnl_name:
    DB 'ntoskrnl.exe', 0
    ALIGN 2
  _IoCreateDevice:
    DW 0
    DB 'IoCreateDevice', 0
    ALIGN 2
  _IoDeleteDevice:
    DW 0
    DB 'IoDeleteDevice', 0
    ALIGN 2
  _IoCreateSymbolicLink:
    DW 0
    DB 'IoCreateSymbolicLink', 0
    ALIGN 2
  _IoDeleteSymbolicLink:
    DW 0
    DB 'IoDeleteSymbolicLink', 0
    ALIGN 2
  _IoCompleteRequest:
    DW 0
    DB 'IoCompleteRequest', 0
    ALIGN 2
  _IoGetCurrentIrpStackLocation:
    DW 0
    DB 'IoGetCurrentIrpStackLocation', 0
    ALIGN 2
  _IoRegisterBootDriverCallback:
    DW 0
    DB 'IoRegisterBootDriverCallback', 0
    ALIGN 2
  _IoUnregisterBootDriverCallback:
    DW 0
    DB 'IoUnregisterBootDriverCallback', 0
    ALIGN 2
  _RtlEqualUnicodeString:
    DW 0
    DB 'RtlEqualUnicodeString', 0
    ALIGN 2
  _IoGetImageCertificateInfo:
    DW 0
    DB 'IoGetImageCertificateInfo', 0