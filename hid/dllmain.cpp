﻿// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include "plog\Log.h"
#include "util.h"
#include "deviceioctl.h"

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		util_init();
		LOGI << "DLL_PROCESS_ATTACH";
		installhooks();
		break;
	case DLL_THREAD_ATTACH:
		LOGI << "DLL_THREAD_ATTACH";
		break;
	case DLL_THREAD_DETACH:
		LOGI << "DLL_THREAD_DETACH";
		break;
	case DLL_PROCESS_DETACH:
		LOGI << "DLL_PROCESS_DETACH";
		util_uninit();
		break;
	}
	return TRUE;
}
