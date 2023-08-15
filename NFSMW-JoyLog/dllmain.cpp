//
// NFS Most Wanted
// JoyLog Control Plugin
// 
// by xan1242 / Tenjoin
//

#include "stdafx.h"
#include "stdio.h"
#include <windows.h>
#include "..\includes\injector\injector.hpp"
#include "..\includes\hooking\Hooking.Patterns.h"
#include "..\includes\IniReader.h"
#include <string>
#include <filesystem>

bool bEnableJoylog = false;
bool bReplayingFlag = false;
std::filesystem::path JoylogReplayFile;
std::filesystem::path JoylogCaptureFile;

// Game pointers
uintptr_t ptrEnableJoylog = 0x9258C8;
uintptr_t ptrJoylog_pReplayingBuffer = 0x009258DC;
uintptr_t ptrJoylog_ReplayingFlag = 0x009258D4;
uintptr_t ptrJoylog_pCapturingBuffer = 0x009258E0;
uintptr_t ptrJoylog_CapturingFlag = 0x009258D8;

uintptr_t ptrbOpen = 0x0065F680;
uintptr_t ptrGetQueuedFileSize = 0x0065F740;
uintptr_t ptrJoylogBufferConstructor = 0x0064C790;

bool bConsoleExists(void)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi))
		return false;

	return true;
}

// custom print methods which include console attachment checks...
int __cdecl cusprintf(const char* Format, ...)
{
	va_list ArgList;
	int Result = 0;

	if (bConsoleExists())
	{
		__crt_va_start(ArgList, Format);
		Result = vprintf(Format, ArgList);
		__crt_va_end(ArgList);
	}

	return Result;
}

int __cdecl cus_puts(char* buf)
{
	if (bConsoleExists())
		return puts(buf);
	return 0;
}

void __cdecl Joylog_Init()
{
	uint32_t v1;
	void* v2;
	FILE *joylogfile;

	if (*(uint32_t*)ptrEnableJoylog)
	{
		if (std::filesystem::exists(JoylogReplayFile) && bReplayingFlag)
		{
			cusprintf("INFO: Opening %s for replaying\n", JoylogReplayFile.string().c_str());
			
			if (reinterpret_cast<void* (*)(const char*, int, int)>(ptrbOpen)(JoylogReplayFile.string().c_str(), 1, 1) == NULL)
			{
				cusprintf("ERROR: Can't open %s for replaying!\n", JoylogReplayFile.c_str());
				return;
			}
			v1 = reinterpret_cast<uint32_t(*)(const char*)>(ptrGetQueuedFileSize)(JoylogReplayFile.string().c_str());
			v2 = malloc(0x4118);
			if (v2)
				reinterpret_cast<void*(__thiscall*)(void*, const char*, int)>(ptrJoylogBufferConstructor)(v2, JoylogReplayFile.string().c_str(), v1);
			*(void**)ptrJoylog_pReplayingBuffer = v2;
			*(uint32_t*)ptrJoylog_ReplayingFlag = 1;
		}
		else
		{
			v2 = malloc(0x4118);
			if (v2)
				reinterpret_cast<void*(__thiscall*)(void*, const char*, int)>(ptrJoylogBufferConstructor)(v2, JoylogCaptureFile.string().c_str(), 0);
			*(void**)ptrJoylog_pCapturingBuffer = v2;
			*(uint32_t*)ptrJoylog_CapturingFlag = 1;
			cusprintf("INFO: Opening %s for capturing\n", JoylogCaptureFile.string().c_str());
			joylogfile = fopen(JoylogCaptureFile.string().c_str(), "wb");
			if (joylogfile)
				fclose(joylogfile);
			else
			{
				cusprintf("ERROR: %s", strerror(errno));
				*(uint32_t*)ptrJoylog_CapturingFlag = 0;
				cusprintf("ERROR: Can't open %s for capturing!\n", JoylogCaptureFile.string().c_str());
			}
		}
	}
}

int Init()
{
	CIniReader inireader("");
	uintptr_t loc_66053E = reinterpret_cast<uintptr_t>(hook::pattern("A1 ? ? ? ? 64 89 25 00 00 00 00 81 EC 08 01 00 00").get_first(0));
	uintptr_t loc_660910 = reinterpret_cast<uintptr_t>(hook::pattern("E8 ? ? ? ? A1 ? ? ? ? 85 C0 74 ? 68 ? ? ? ? E8").get_first(0));
	uintptr_t loc_660591 = reinterpret_cast<uintptr_t>(hook::pattern("68 18 41 00 00 8B F0 E8").get_first(0)) - 0xF;
	uintptr_t loc_66059B = loc_660591 + 0xA;
	uintptr_t loc_6605CA = loc_660591 + 0x39;
	uintptr_t loc_6605D3 = loc_660591 + 0x42;
	uintptr_t loc_6605D8 = loc_660591 + 0x47;
	uintptr_t loc_66063D = reinterpret_cast<uintptr_t>(hook::pattern("6A 01 6A 06 68 ? ? ? ? C7 84 24 1C 01 00 00 FF FF FF FF").get_first(0)) + 0x14;
	uintptr_t loc_660642 = loc_66063D + 5;

	ptrEnableJoylog = *(uintptr_t*)(loc_66053E + 1);
	ptrJoylog_pReplayingBuffer = *(uintptr_t*)(loc_6605D3 + 1);
	ptrJoylog_ReplayingFlag = *(uintptr_t*)(loc_6605D8 + 2);
	ptrJoylog_pCapturingBuffer = *(uintptr_t*)(loc_66063D + 1);
	ptrJoylog_CapturingFlag = *(uintptr_t*)(loc_660642 + 2);

	ptrbOpen = static_cast<uintptr_t>(injector::GetBranchDestination(loc_660591));
	ptrGetQueuedFileSize = static_cast<uintptr_t>(injector::GetBranchDestination(loc_66059B));
	ptrJoylogBufferConstructor = static_cast<uintptr_t>(injector::GetBranchDestination(loc_6605CA));

	*(uint32_t*)ptrEnableJoylog = inireader.ReadInteger("Joylog", "EnableJoylog", 0);
	bReplayingFlag = inireader.ReadInteger("Joylog", "ReplayingFlag", 0);
	JoylogReplayFile = inireader.ReadString("Joylog", "JoylogReplayFile", "ReplayJoylog.jlg");
	JoylogCaptureFile = inireader.ReadString("Joylog", "JoylogCaptureFile", "CaptureJoylog.jlg");


	injector::MakeCALL(loc_660910, Joylog_Init, true);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE /*hModule*/, DWORD reason, LPVOID /*lpReserved*/)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		if (bConsoleExists())
		{
			freopen("CON", "w", stdout);
			freopen("CON", "w", stderr);
		}
		Init();
	}
	return TRUE;
}

