/*
 * HID spoofing.
 */
#pragma once

#include "stdafx.h"

#define HIDDLLPATH "C:\\Windows\\System32\\hid.dll"

typedef struct HIDD_ATTRIBUTES {
	ULONG  Size;
	USHORT VendorID;
	USHORT ProductID;
	USHORT VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

typedef BOOLEAN(__stdcall *HidD_GetAttributes_t)(
	_In_  HANDLE           HidDeviceObject,
	_Out_ PHIDD_ATTRIBUTES Attributes
);
typedef BOOLEAN(__stdcall *HidD_GetManufacturerString_t)(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
);
typedef BOOLEAN(__stdcall *HidD_GetSerialNumberString_t)(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
);
typedef BOOLEAN(__stdcall *HidD_GetProductString_t)(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
);
typedef void(__stdcall *HidD_GetHidGuid_t)(
	_Out_ LPGUID HidGuid
);
typedef BOOLEAN(__stdcall *HidD_SetFeature_t)(
	_In_ HANDLE HidDeviceObject,
	_In_ PVOID  ReportBuffer,
	_In_ ULONG  ReportBufferLength
);
