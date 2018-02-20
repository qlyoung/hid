#include "stdafx.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#include "plog\Log.h"
#include "deviceioctl.h"
#include "util.h"
#include "MinHook.h"
#include "SetupAPI.h"
#include <sstream>
#include <string>

#define DEF_HOOK(rt, cc, name, ...) \
	typedef rt (cc * name##_t)(__VA_ARGS__); \
	name##_t orig_##name; \
	rt cc hook_##name(__VA_ARGS__)

#define ADD_HOOK(fn) \
	if (MH_CreateHook(&fn, &hook_##fn, reinterpret_cast<LPVOID *>(&orig_##fn)) != MH_OK) \
		LOGE << "Could not create " #fn " hook."; \
	if (MH_EnableHook(&fn) != MH_OK) \
		LOGE << "Could not enable hook_" #fn;

#define LOG_SETUPDIGETCLASSDEVS(guid) \
	{ \
		std::stringstream logmsg; \
		char buf[128]; \
		if (guid) { \
			snprintf(buf, sizeof(buf), "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", \
				guid##->Data1, guid##->Data2, guid##->Data3, \
				guid##->Data4[0], guid##->Data4[1], guid##->Data4[2], guid##->Data4[3], \
				guid##->Data4[4], guid##->Data4[5], guid##->Data4[6], guid##->Data4[7]); \
			logmsg << buf; \
		} \
		else \
			logmsg << "All"; \
		LOGI << "Requested class devs for class GUID: " << buf; \
	}


/* Imports from SETUPAPI.dll:

SETUPAPI.dll
	14072CAA0 Import Address Table
	140B717C8 Import Name Table
	0 time date stamp
	0 Index of first forwarder reference

	6A CM_Get_Device_Interface_List_SizeA
	66 CM_Get_Device_Interface_ListA
	19F SetupDiGetClassDevsExW
	19D SetupDiGetClassDevsA
	54 CM_Get_Device_IDA
	1BC SetupDiGetDevicePropertyW
	1A0 SetupDiGetClassDevsW
	189 SetupDiDestroyDeviceInfoList
	18C SetupDiEnumDeviceInfo
	1BE SetupDiGetDeviceRegistryPropertyW
	80 CM_Get_Parent
	55 CM_Get_Device_IDW
	1B7 SetupDiGetDeviceInterfaceDetailA
	1B8 SetupDiGetDeviceInterfaceDetailW
	18D SetupDiEnumDeviceInterfaces
*/

DEF_HOOK(HANDLE, WINAPI, CreateFileW,
	_In_     LPCWSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
)
{
	if (wcsncmp(lpFileName, L"C:\\", wcslen(L"C:\\")))
		LOGI << lpFileName;
	return orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

DEF_HOOK(HDEVINFO, , SetupDiGetClassDevsW,
	_In_opt_   const GUID     *ClassGuid,
	_In_opt_         PCWSTR   Enumerator,
	_In_opt_         HWND     hwndParent,
	_In_             DWORD    Flags
)
{
	LOG_SETUPDIGETCLASSDEVS(ClassGuid);
	HDEVINFO ret = orig_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent, Flags);
	return ret;
}

DEF_HOOK(HDEVINFO, , SetupDiGetClassDevsExW,
	_In_opt_   const GUID     *ClassGuid,
	_In_opt_         PCWSTR   Enumerator,
	_In_opt_         HWND     hwndParent,
	_In_             DWORD    Flags,
	_In_opt_         HDEVINFO DeviceInfoSet,
	_In_opt_         PCWSTR   MachineName,
	_Reserved_       PVOID    Reserved
)
{
	LOG_SETUPDIGETCLASSDEVS(ClassGuid);
	HDEVINFO ret = orig_SetupDiGetClassDevsExW(ClassGuid, Enumerator, hwndParent, Flags, DeviceInfoSet, MachineName, Reserved);
	return ret;
}

DEF_HOOK(HDEVINFO, , SetupDiGetClassDevsA,
	_In_opt_   const GUID     *ClassGuid,
	_In_opt_         PCSTR    Enumerator,
	_In_opt_         HWND     hwndParent,
	_In_             DWORD    Flags
)
{
	LOG_SETUPDIGETCLASSDEVS(ClassGuid);
	HDEVINFO ret = orig_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent, Flags);
	return ret;
}

DEF_HOOK(BOOL, , SetupDiEnumDeviceInfo,
	_In_  HDEVINFO         DeviceInfoSet,
	_In_  DWORD            MemberIndex,
	_Out_ PSP_DEVINFO_DATA DeviceInfoData
)
{
	BOOL ret;
	LOGI << "Requested information on member " << MemberIndex;
	ret = orig_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);
	return ret;
}

DEF_HOOK(BOOL, WINAPI, DeviceIoControl,
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped)
{
	BOOL ret;
	std::stringstream logmsg;
	static HANDLE sensor;

	if (!sensor && dwIoControlCode == SENSOR_IOCTL_UNKNOWN) {
		logmsg << "Saw probable sensor IOCTL, saving handle";
		sensor = hDevice;
	}

	if (sensor && hDevice == sensor) {
		logmsg << std::endl << "===== IOCTL =====" << std::endl;
		logmsg << "ctlcode: " << dwIoControlCode << std::endl;
		logmsg << "overlapped: " << std::hex << lpOverlapped << std::dec << std::endl;
		logmsg << "inbuf[" << nInBufferSize << "]" << std::endl;
		logmsg << hexdump(lpInBuffer, nInBufferSize);
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
			nInBufferSize, lpOutBuffer,
			nOutBufferSize, lpBytesReturned,
			lpOverlapped);
		logmsg << "bytes returned: " << (lpBytesReturned ? *lpBytesReturned : 0);
		logmsg << (lpBytesReturned ? "" : "(dumping whole buffer)") << std::endl;
		if (lpOutBuffer) {
			logmsg << "obuf[" << nOutBufferSize << "]" << std::endl;
			logmsg << hexdump(lpOutBuffer, lpBytesReturned ? *lpBytesReturned : nOutBufferSize);
		}
		logmsg << "=================" << std::endl;
	}
	else {
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
			nInBufferSize, lpOutBuffer,
			nOutBufferSize, lpBytesReturned,
			lpOverlapped);
	}

	if (logmsg.rdbuf()->in_avail())
		LOGI << logmsg.str();

	return ret;
}


void installhooks()
{
	if (MH_Initialize() != MH_OK)
		LOGE << "Could not initialize MinHook.";

	ADD_HOOK(CreateFileW);
	ADD_HOOK(SetupDiGetClassDevsW);
	ADD_HOOK(SetupDiGetClassDevsExW);
	ADD_HOOK(SetupDiGetClassDevsA);
	ADD_HOOK(SetupDiEnumDeviceInfo);
	ADD_HOOK(DeviceIoControl);


	LOGI << "Installed hooks.";
}
