// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "common.h"
#include <stdio.h>
#include "include\MinHook.h"

FILE *logfile;
HMODULE hid;

HidD_GetAttributes_t real_HidD_GetAttributes;
HidD_GetManufacturerString_t real_HidD_GetManufacturerString;
HidD_GetSerialNumberString_t real_HidD_GetSerialNumberString;
HidD_GetProductString_t real_HidD_GetProductString;
HidD_GetHidGuid_t real_HidD_GetHidGuid;
HidD_SetFeature_t real_HidD_SetFeature;

DeviceIoControl_t hook_DeviceIoControl;

void mwLog(const wchar_t *format, ...)
{
	logfile = logfile ? logfile : fopen(logfilename, "w");
	va_list args;
	va_start(args, format);
	vfwprintf(logfile, format, args);
	va_end(args);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);
}

void mLog(const char *format, ...)
{
	logfile = logfile ? logfile : fopen(logfilename, "w");
	va_list args;
	va_start(args, format);
	vfprintf(logfile, format, args);
	va_end(args);
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

