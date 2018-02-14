// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "common.h"
#include <stdio.h>
#include "MinHook.h"

FILE *logfile;
HMODULE hid;

HidD_GetAttributes_t real_HidD_GetAttributes;
HidD_GetManufacturerString_t real_HidD_GetManufacturerString;
HidD_GetSerialNumberString_t real_HidD_GetSerialNumberString;
HidD_GetProductString_t real_HidD_GetProductString;
HidD_GetHidGuid_t real_HidD_GetHidGuid;
HidD_SetFeature_t real_HidD_SetFeature;

DeviceIoControl_t hook_DeviceIoControl;

void mLog(const char *message)
{
	logfile = logfile ? logfile : fopen(logfilename, "w");
	fwrite(message, 1, strlen(message), logfile);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);
}


void CreateHooks()
{
	if (MH_Initialize() != MH_OK)
		mLog("[X] Could not initialize MinHook.");
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		mLog("[+] DLL_PROCESS_ATTACH");
		break;
	case DLL_THREAD_ATTACH:
		mLog("[+] DLL_THREAD_ATTACH");
		break;
	case DLL_THREAD_DETACH:
		mLog("[+] DLL_THREAD_DETACH");
		break;
	case DLL_PROCESS_DETACH:
		mLog("[+] DLL_PROCESS_DETACH");
		fclose(logfile);
		logfile = NULL;
		break;
	}
	return TRUE;
}

