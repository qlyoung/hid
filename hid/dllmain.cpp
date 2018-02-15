// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include "util.h"
#include "hid.h"
#include "deviceioctl.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		util_init();
		mlog("[+] DLL_PROCESS_ATTACH");
		installhooks();
		break;
	case DLL_THREAD_ATTACH:
		mlog("[+] DLL_THREAD_ATTACH");
		break;
	case DLL_THREAD_DETACH:
		mlog("[+] DLL_THREAD_DETACH");
		break;
	case DLL_PROCESS_DETACH:
		mlog("[+] DLL_PROCESS_DETACH");
		util_uninit();
		break;
	}
	return TRUE;
}
