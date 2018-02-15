// hid.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "common.h"
#include "atlstr.h"  


#define HIDPRELUDE(fname) \
	do { \
		mLog("[+] Called " #fname); \
		if (!hid) { \
			hid = LoadLibraryA(hiddllpath); \
			mLog("[!] Loading hid.dll %s",  (hid ? "succeeded" : "failed")); \
		} \
		if (!real_##fname) { \
			real_##fname = (fname##_t) GetProcAddress(hid, #fname); \
			mLog("[!] Loaded %s at %p", #fname, real_##fname); \
		} \
	} while (0);

BOOLEAN __stdcall HidD_GetAttributes(
	_In_  HANDLE           HidDeviceObject,
	_Out_ PHIDD_ATTRIBUTES Attributes
)
{
	BOOLEAN ret;
	HIDPRELUDE(HidD_GetAttributes);

	ret = real_HidD_GetAttributes(HidDeviceObject, Attributes);
	mLog("[+] %s: %s ", __func__, ret ? "succeeded" : "failed");
	if (ret) {
		mLog(">>> Size: %lu", Attributes->Size);
		mLog(">>> VendorID: %u", Attributes->VendorID);
		mLog(">>> ProductID: %u", Attributes->ProductID);
		mLog(">>> VersionNumber: %u", Attributes->VersionNumber);
	}
	return ret;
}

BOOLEAN __stdcall HidD_GetManufacturerString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	HIDPRELUDE(HidD_GetManufacturerString);

	ret = real_HidD_GetManufacturerString(HidDeviceObject, Buffer, BufferLength);
	mLog("[+] %s: %s", __func__, ret ? "succeeded" : "failed");
	if (ret)
		mwLog(L">>> Manufacturer: (%lu) %s", BufferLength, Buffer);
	return ret;
}

BOOLEAN __stdcall HidD_GetSerialNumberString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	HIDPRELUDE(HidD_GetSerialNumberString);

	ret = real_HidD_GetSerialNumberString(HidDeviceObject, Buffer, BufferLength);
	mLog("[+] %s: %s", __func__, ret ? "succeeded" : "failed");
	if (ret)
		mwLog(L">>> Serial number: (%lu) %s", BufferLength, Buffer);
	return ret;
}

BOOLEAN __stdcall HidD_GetProductString(
	_In_  HANDLE HidDeviceObject,
	_Out_ PVOID  Buffer,
	_In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	HIDPRELUDE(HidD_GetProductString);

	ret = real_HidD_GetProductString(HidDeviceObject, Buffer, BufferLength);
	mLog("[+] %s: %s", __func__, ret ? "succeeded" : "failed");
	if (ret)
		mwLog(L">>> Product: (%lu) %s", BufferLength, Buffer);
	return ret;
}

void __stdcall HidD_GetHidGuid(
	_Out_ LPGUID HidGuid
)
{
	HIDPRELUDE(HidD_GetHidGuid);

	real_HidD_GetHidGuid(HidGuid);

	mLog(">>> HidGuid: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
		HidGuid->Data1, HidGuid->Data2, HidGuid->Data3,
		HidGuid->Data4[0], HidGuid->Data4[1], HidGuid->Data4[2], HidGuid->Data4[3],
		HidGuid->Data4[4], HidGuid->Data4[5], HidGuid->Data4[6], HidGuid->Data4[7]);
}

BOOLEAN __stdcall HidD_SetFeature(
	_In_ HANDLE HidDeviceObject,
	_In_ PVOID  ReportBuffer,
	_In_ ULONG  ReportBufferLength
)
{
	BOOLEAN ret;
	HIDPRELUDE(HidD_SetFeature);

	ret = real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);
	mLog("[+] %s: %s", __func__, ret ? "succeeded" : "failed");
	if (ret)
		mLog(">>> Report as hex: %.*x", ReportBufferLength, ReportBuffer);
	return ret;
}
