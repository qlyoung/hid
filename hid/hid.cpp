// hid.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "common.h"
#include <stdio.h>

#define HIDPRELUDE(fname) \
	do { \
		mLog("[+] " #fname); \
		if (!hid) \
			hid = LoadLibraryA("hid.dll"); \
		if (!real_##fname) { \
			real_##fname = (fname##_t) GetProcAddress(hid, #fname); \
			char pbuf[128]; \
			snprintf(pbuf, sizeof(pbuf), "[!] Loaded %s at %p", #fname, real_##fname); \
			mLog(pbuf); \
		} \
	} while (0);

BOOLEAN __stdcall HidD_GetAttributes(
	_In_  HANDLE           HidDeviceObject,
	_Out_ PHIDD_ATTRIBUTES Attributes
)
{
	HIDPRELUDE(HidD_GetAttributes);
	return real_HidD_GetAttributes(HidDeviceObject, Attributes);
}

BOOLEAN __stdcall HidD_GetManufacturerString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	HIDPRELUDE(HidD_GetManufacturerString);
	return real_HidD_GetManufacturerString(HidDeviceObject, Buffer, BufferLength);
}

BOOLEAN __stdcall HidD_GetSerialNumberString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	HIDPRELUDE(HidD_GetSerialNumberString);
	return real_HidD_GetSerialNumberString(HidDeviceObject, Buffer, BufferLength);
}

BOOLEAN __stdcall HidD_GetProductString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	HIDPRELUDE(HidD_GetProductString);
	return real_HidD_GetProductString(HidDeviceObject, Buffer, BufferLength);
}

void __stdcall HidD_GetHidGuid(
	_Out_ LPGUID HidGuid
)
{
	HIDPRELUDE(HidD_GetHidGuid);
	return real_HidD_GetHidGuid(HidGuid);
}

BOOLEAN __stdcall HidD_SetFeature(
	_In_ HANDLE HidDeviceObject,
	_In_ PVOID  ReportBuffer,
	_In_ ULONG  ReportBufferLength
)
{
	HIDPRELUDE(HidD_SetFeature);
	return real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
}
