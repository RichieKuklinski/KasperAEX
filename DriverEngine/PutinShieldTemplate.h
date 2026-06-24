#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
LARGE_INTEGER g_CallbackRegistrationCookie;
LIST_ENTRY LoadedImageListHead;
FAST_MUTEX ImageListMutex;
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


// ========================================

constexpr ULONG BLACKLIST_COUNT = 50;

inline const wchar_t* BlackListNames[BLACKLIST_COUNT] =
{
    L"gdrv.sys",            // Gigabyte App Center (Ggdrv)
    L"RTCore64.sys",        // MSI Afterburner
    L"RTCore32.sys",        // MSI Afterburner (32-bit)
    L"procexp.sys",         // Sysinternals Process Explorer (старые версии)
    L"speedfan.sys",        // SpeedFan utility
    L"atoc032.sys",         // ATI Technologies / AMD
    L"atiilhag.sys",        // AMD/ATI Radeon
    L"ENE.sys",             // ENE Technology RGB / Hardware Monitor
    L"EneTechIo64.sys",     // ENE Technology Io Control
    L"AsIO.sys",            // ASUS Aura / ASUS Software
    L"AsAsIO2.sys",         // ASUS Utility
    L"GLCKIO2.sys",         // ASUS ROG Aura Service
    L"mhyprot2.sys",        // miHoYo Anti-Cheat (Genshin Impact)
    L"ACE-BASE.sys",        // Anti-Cheat Expert (Tencent)
    L"PhMyComputer64.sys",  // Process Hacker 
    L"kprocesshacker.sys",  // Process Hacker / System Informer
    L"NalDrv.sys",          // Intel Network Adapter Diagnostic
    L"iqvw64e.sys",         // Intel Ethernet Network Connection
    L"iqvw32e.sys",         // Intel Ethernet Network Connection (32-bit)
    L"cpuz141.sys",         // CPUID CPU-Z
    L"cpuz152.sys",         // CPUID CPU-Z
    L"cpuz154.sys",         // CPUID CPU-Z
    L"MsIo64.sys",          // Patriot Viper RGB / MSI
    L"ALSysIO64.sys",       // Core Temp
    L"DBUtil_2_3.sys",      // Dell Firmware Update Utility
    L"dbutil_2_5.sys",      // Dell Firmware Update Utility
    L"ENECC64.sys",         // Control Center (Clevo/Gigabyte)
    L"GVTDrv64.sys",        // Gigabyte EasyTune
    L"PhlashNT.sys",        // Phoenix Technologies BIOS tool
    L"winring0.sys",        // WinRing0 (Open Hardware Monitor)
    L"WinRing0x64.sys",     // WinRing0 (64-bit variant)
    L"SuperVerg.sys",       // Realtek Wireless Utility
    L"rtwlane.sys",         // Realtek Wireless LAN driver
    L"Capcom.sys",          // Capcom Street Fighter V (известен отключением SMEP)
    L"rwdrv.sys",           // Read-Write Driver utility
    L"rzwmioctl.sys",       // Razer Chroma SDK
    L"adv64safe.sys",       // Advanced SystemCare (IObit)
    L"iobitutil.sys",       // IObit Uninstaller / SystemCare
    L"DirectIo.sys",        // DirectIO system utility
    L"PDFWKRNL.sys",        // Promptard / PDF Password Remover
    L"Reggard.sys",         // Registry Guard utility
    L"GamesGuard.sys",      // NetEase Games Guard
    L"PHYMEM.sys",          // PhyMem Memory access driver
    L"pcregdrv.sys",        // PC Mechanic Registry driver
    L"ksapi64.sys",         // Kaspersky Anti-Virus (старые версии Kingsoft)
    L"truesight.sys",       // TrueSight / CyberArk endpoint
    L"Netfilter.sys",       // Netfilter network driver
    L"PCHunter64.sys",      // PC Hunter kernel tool
    L"PowerTool64.sys",     // XueTr / PowerTool kernel utility
    L"GMER.sys"             // GMER Anti-Rootkit
};

namespace shield::anti_exploit 
{
    inline void check_thread_token(HANDLE process_id);
    inline void save_original_token(HANDLE process_id);
}

namespace shield::monitor
{
    inline void save_loaded_image(PUNICODE_STRING image_name, HANDLE process_id, PIMAGE_INFO image_info);
}

namespace shield::getdriverlist
{
   inline NTSTATUS driverlist(PUNICODE_STRING DriverName, PIMAGE_INFO ImageInfo);
}
