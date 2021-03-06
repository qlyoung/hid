﻿#include "stdafx.h"

#include "hid.h"
#include "util.h"
#include "plog\Log.h"
#include <atomic>
#include <sstream>

std::atomic_flag hid_loaded;
HMODULE hid;

/*
 * Quick and dirty init macro. Lazy loads functions from hid.dll as needed.
 * Also loads hid.dll if it is not loaded yet.
 */
#define HIDPRELUDE(fname) \
	static std::atomic_flag loaded_##fname; \
	static fname##_t real_##fname; \
	if (!std::atomic_flag_test_and_set(&hid_loaded)) { \
		hid = LoadLibraryA(HIDDLLPATH); \
		LOGI << "Loading hid.dll " << (hid ? "succeeded" : "failed"); \
	} \
	if (!std::atomic_flag_test_and_set(&loaded_##fname)) { \
		real_##fname = (fname##_t) GetProcAddress(hid, #fname); \
		LOGI << "Loaded "#fname" at " << std::hex << real_##fname; \
	}

BOOLEAN __stdcall HidD_GetAttributes(
        _In_  HANDLE           HidDeviceObject,
        _Out_ PHIDD_ATTRIBUTES Attributes
)
{
	BOOLEAN ret;
	std::stringstream logmsg;
	HIDPRELUDE(HidD_GetAttributes);

	ret = real_HidD_GetAttributes(HidDeviceObject, Attributes);

	logmsg << (ret ? "succeeded" : "failed") << std::endl;
	if (ret) {
		logmsg << ">>> Size: " << Attributes->Size << std::endl;
		logmsg << ">>> VendorID: " << Attributes->VendorID << std::endl;
		logmsg << ">>> ProductID: " << Attributes->ProductID << std::endl;
		logmsg << ">>> VersionNumber: " << Attributes->VersionNumber << std::endl;
	}
	LOGI << logmsg.str();

	return ret;
}

BOOLEAN __stdcall HidD_GetManufacturerString(
        _In_  HANDLE HidDeviceObject,
        _Out_ PVOID  Buffer,
        _In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	std::wstringstream logmsg;
	HIDPRELUDE(HidD_GetManufacturerString);

	ret = real_HidD_GetManufacturerString(HidDeviceObject, Buffer, BufferLength);

	logmsg << (ret ? L"succeeded" : L"failed") << std::endl;
	if (ret) {
		std::wstring mf((wchar_t *) Buffer, BufferLength);
		logmsg << L">>> Manufacturer: (" << BufferLength << L") " << mf;
	}
	LOGI << logmsg.str();

	return ret;
}

BOOLEAN __stdcall HidD_GetSerialNumberString(
        _In_  HANDLE HidDeviceObject,
        _Out_ PVOID  Buffer,
        _In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	std::wstringstream logmsg;
	HIDPRELUDE(HidD_GetSerialNumberString);

	ret = real_HidD_GetSerialNumberString(HidDeviceObject, Buffer, BufferLength);

	logmsg << (ret ? L"succeeded" : L"failed") << std::endl;
	if (ret) {
		std::wstring sn((wchar_t *)Buffer, BufferLength);
		logmsg << ">>> Serial number: (" << BufferLength << ") " << sn;
	}

	LOGI << logmsg.str();

	return ret;
}

BOOLEAN __stdcall HidD_GetProductString(
        _In_  HANDLE HidDeviceObject,
        _Out_ PVOID  Buffer,
        _In_  ULONG  BufferLength
)
{
	BOOLEAN ret;
	std::wstringstream logmsg;
	HIDPRELUDE(HidD_GetProductString);

	ret = real_HidD_GetProductString(HidDeviceObject, Buffer, BufferLength);

	logmsg << (ret ? L"succeeded" : L"failed") << std::endl;
	if (ret) {
		std::wstring p((wchar_t *)Buffer, BufferLength);
		logmsg << L">>> Product: (" << BufferLength << ") " << p << std::endl;
	}
	LOGI << logmsg.str();

	return ret;
}

void __stdcall HidD_GetHidGuid(
        _Out_ LPGUID HidGuid
)
{
	HIDPRELUDE(HidD_GetHidGuid);

	real_HidD_GetHidGuid(HidGuid);
	char buf[128];
	snprintf(buf, sizeof(buf),
	         ">>> HidGuid: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
	         HidGuid->Data1, HidGuid->Data2, HidGuid->Data3,
	         HidGuid->Data4[0], HidGuid->Data4[1], HidGuid->Data4[2], HidGuid->Data4[3],
	         HidGuid->Data4[4], HidGuid->Data4[5], HidGuid->Data4[6], HidGuid->Data4[7]);
	LOGI << buf << std::endl;
}

BOOLEAN __stdcall HidD_SetFeature(
        _In_ HANDLE HidDeviceObject,
        _In_ PVOID  ReportBuffer,
        _In_ ULONG  ReportBufferLength
)
{
	BOOLEAN ret;
	std::stringstream logmsg;
	HIDPRELUDE(HidD_SetFeature);

	ret = real_HidD_SetFeature(HidDeviceObject, ReportBuffer, ReportBufferLength);

	logmsg << (ret ? "succeeded" : "failed") << std::endl;
	if (ret) {
		logmsg << ">>> Report as hex: " << std::endl;
		logmsg << hexdump(ReportBuffer, ReportBufferLength) << std::endl;
	}
	LOGI << logmsg.str();

	return ret;
}
