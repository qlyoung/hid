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
#include "Dbt.h"
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
	if (guid) { \
		LOGI << "Requested class devs for class GUID: " << guid2str(guid);  \
	} \
	else \
		LOGI << "Requested devices for all classes";

std::string psp_devinfo_data2str(PSP_DEVINFO_DATA pdd)
{
	std::stringstream wb;
	wb << "Size: " << pdd->cbSize << std::endl;
	wb << "GUID: " << guid2str(&pdd->ClassGuid) << std::endl;
	wb << "DevInst: " << pdd->DevInst;
	return std::string(wb.str());
}

/* Imports from SETUPAPI.dll:

SETUPAPI.dll
	14072CAA0 Import Address Table
	140B717C8 Import Name Table
	0 time date stamp
	0 Index of first forwarder reference

	  6A CM_Get_Device_Interface_List_SizeA
	  66 CM_Get_Device_Interface_ListA
	* 19F SetupDiGetClassDevsExW
	* 19D SetupDiGetClassDevsA
	  54 CM_Get_Device_IDA
	* 1BC SetupDiGetDevicePropertyW
	* 1A0 SetupDiGetClassDevsW
	  189 SetupDiDestroyDeviceInfoList
	* 18C SetupDiEnumDeviceInfo
	  1BE SetupDiGetDeviceRegistryPropertyW
	  80 CM_Get_Parent
	  55 CM_Get_Device_IDW
	* 1B7 SetupDiGetDeviceInterfaceDetailA
	* 1B8 SetupDiGetDeviceInterfaceDetailW
	* 18D SetupDiEnumDeviceInterfaces
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
	return orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
	                        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes,
	                        hTemplateFile);
}

DEF_HOOK(HDEVINFO,, SetupDiGetClassDevsW,
         _In_opt_   const GUID     *ClassGuid,
         _In_opt_         PCWSTR   Enumerator,
         _In_opt_         HWND     hwndParent,
         _In_             DWORD    Flags
        )
{
	LOG_SETUPDIGETCLASSDEVS(ClassGuid);
	HDEVINFO ret = orig_SetupDiGetClassDevsW(ClassGuid, Enumerator, hwndParent,
	                Flags);
	return ret;
}

DEF_HOOK(HDEVINFO,, SetupDiGetClassDevsExW,
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
	HDEVINFO ret = orig_SetupDiGetClassDevsExW(ClassGuid, Enumerator, hwndParent,
	                Flags, DeviceInfoSet, MachineName, Reserved);
	return ret;
}

DEF_HOOK(HDEVINFO,, SetupDiGetClassDevsA,
         _In_opt_   const GUID     *ClassGuid,
         _In_opt_         PCSTR    Enumerator,
         _In_opt_         HWND     hwndParent,
         _In_             DWORD    Flags
        )
{
	LOG_SETUPDIGETCLASSDEVS(ClassGuid);
	HDEVINFO ret = orig_SetupDiGetClassDevsA(ClassGuid, Enumerator, hwndParent,
	                Flags);
	return ret;
}

DEF_HOOK(BOOL,, SetupDiEnumDeviceInfo,
         _In_  HDEVINFO         DeviceInfoSet,
         _In_  DWORD            MemberIndex,
         _Out_ PSP_DEVINFO_DATA DeviceInfoData
        )
{
	BOOL ret;
	std::stringstream logmsg;
	LOGI << "Requested information on member: " << MemberIndex;
	ret = orig_SetupDiEnumDeviceInfo(DeviceInfoSet, MemberIndex, DeviceInfoData);
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	LOGI << logmsg.str();
	return ret;
}

DEF_HOOK(BOOL,, SetupDiGetDeviceInterfaceDetailA,
         _In_      HDEVINFO                           DeviceInfoSet,
         _In_      PSP_DEVICE_INTERFACE_DATA          DeviceInterfaceData,
         _Out_opt_ PSP_DEVICE_INTERFACE_DETAIL_DATA_A DeviceInterfaceDetailData,
         _In_      DWORD                              DeviceInterfaceDetailDataSize,
         _Out_opt_ PDWORD                             RequiredSize,
         _Out_opt_ PSP_DEVINFO_DATA                   DeviceInfoData
        )
{
	BOOL ret;
	std::stringstream logmsg;
	ret = orig_SetupDiGetDeviceInterfaceDetailA(DeviceInfoSet,
	                DeviceInterfaceData,
	                DeviceInterfaceDetailData,
	                DeviceInterfaceDetailDataSize,
	                RequiredSize, DeviceInfoData);
	logmsg << "Requested device interface details";
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	LOGI << logmsg.str();
	return ret;
}

DEF_HOOK(BOOL,, SetupDiGetDeviceInterfaceDetailW,
         _In_      HDEVINFO                           DeviceInfoSet,
         _In_      PSP_DEVICE_INTERFACE_DATA          DeviceInterfaceData,
         _Out_opt_ PSP_DEVICE_INTERFACE_DETAIL_DATA_W DeviceInterfaceDetailData,
         _In_      DWORD                              DeviceInterfaceDetailDataSize,
         _Out_opt_ PDWORD                             RequiredSize,
         _Out_opt_ PSP_DEVINFO_DATA                   DeviceInfoData
        )
{
	BOOL ret;
	std::stringstream logmsg;
	ret = orig_SetupDiGetDeviceInterfaceDetailW(DeviceInfoSet,
	                DeviceInterfaceData,
	                DeviceInterfaceDetailData,
	                DeviceInterfaceDetailDataSize,
	                RequiredSize, DeviceInfoData);
	logmsg << "Requested device interface details";
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	LOGI << logmsg.str();
	return ret;
}

DEF_HOOK(BOOL,, SetupDiEnumDeviceInterfaces,
         _In_           HDEVINFO                  DeviceInfoSet,
         _In_opt_       PSP_DEVINFO_DATA          DeviceInfoData,
         _In_     const GUID                      *InterfaceClassGuid,
         _In_           DWORD                     MemberIndex,
         _Out_          PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData
        )
{
	std::stringstream logmsg;
	logmsg << "Requested enumeration of device interface @ index: " << MemberIndex;
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	LOGI << logmsg.str();
	return orig_SetupDiEnumDeviceInterfaces(
	               DeviceInfoSet,
	               DeviceInfoData,
	               InterfaceClassGuid,
	               MemberIndex,
	               DeviceInterfaceData);
}

DEF_HOOK(BOOL,, SetupDiGetDevicePropertyW,
         _In_            HDEVINFO         DeviceInfoSet,
         _In_            PSP_DEVINFO_DATA DeviceInfoData,
         _In_      const DEVPROPKEY       *PropertyKey,
         _Out_           DEVPROPTYPE      *PropertyType,
         _Out_opt_       PBYTE            PropertyBuffer,
         _In_            DWORD            PropertyBufferSize,
         _Out_opt_       PDWORD           RequiredSize,
         _In_            DWORD            Flags /* always zero */
        )
{
	BOOL ret;
	std::stringstream logmsg;
	ret = orig_SetupDiGetDevicePropertyW(
	              DeviceInfoSet,
	              DeviceInfoData,
	              PropertyKey,
	              PropertyType,
	              PropertyBuffer,
	              PropertyBufferSize,
	              RequiredSize,
	              Flags);
	logmsg << "Requested device property";
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	if (PropertyBuffer) {
		DWORD psz = RequiredSize ? *RequiredSize : PropertyBufferSize;
		logmsg << "Received property:";
		logmsg << std::endl << hexdump(PropertyBuffer, psz);
	}
	LOGI << logmsg.str();
	return ret;
}

DEF_HOOK(BOOL,, SetupDiGetDeviceRegistryProperty,
         _In_      HDEVINFO         DeviceInfoSet,
         _In_      PSP_DEVINFO_DATA DeviceInfoData,
         _In_      DWORD            Property,
         _Out_opt_ PDWORD           PropertyRegDataType,
         _Out_opt_ PBYTE            PropertyBuffer,
         _In_      DWORD            PropertyBufferSize,
         _Out_opt_ PDWORD           RequiredSize
        )
{
	BOOL ret;
	std::stringstream logmsg;
	ret = orig_SetupDiGetDeviceRegistryProperty(DeviceInfoSet, DeviceInfoData,
	                Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize,
	                RequiredSize);
	logmsg << "Requested device registry property w/ key: " << Property <<
	       std::endl;
	if (DeviceInfoData)
		logmsg << std::endl << psp_devinfo_data2str(DeviceInfoData) << std::endl;
	if (PropertyBuffer) {
		DWORD psz = RequiredSize ? *RequiredSize : PropertyBufferSize;
		logmsg << "Received property:";
		logmsg << std::endl << hexdump(PropertyBuffer, psz);
	}
	LOGI << logmsg.str();
	return ret;
}

DEF_HOOK(HDEVNOTIFY, WINAPI, RegisterDeviceNotificationW,
         _In_ HANDLE hRecipient,
         _In_ LPVOID NotificationFilter,
         _In_ DWORD  Flags
        )
{
	size_t hdrsize;
	std::stringstream logmsg;
	logmsg << "Registered device notification: " << std::endl;
	PDEV_BROADCAST_HDR bchdr = reinterpret_cast<PDEV_BROADCAST_HDR>
	                           (NotificationFilter);
	logmsg << "Size: " << bchdr->dbch_size << std::endl;
	logmsg << "Device type: " << bchdr->dbch_devicetype;
	logmsg << " (" << (bchdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE ?
	                   "DBT_DEVTYP_DEVICEINTERFACE" : "DBT_DEVTYP_HANDLE") << ")" << std::endl;
	logmsg << "Reserved: " << bchdr->dbch_reserved << std::endl;
	logmsg << "Body: " << std::endl;
	hdrsize = sizeof(DEV_BROADCAST_HDR);
	logmsg << hexdump(((char *)bchdr) + hdrsize, bchdr->dbch_size - hdrsize);
	LOGI << logmsg.str();
	return orig_RegisterDeviceNotificationW(hRecipient, NotificationFilter, Flags);
}

DEF_HOOK(BOOL, WINAPI, DeviceIoControl,
         _In_        HANDLE       hDevice,
         _In_        DWORD        dwIoControlCode,
         _In_opt_    LPVOID       lpInBuffer,
         _In_        DWORD        nInBufferSize,
         _Out_opt_   LPVOID       lpOutBuffer,
         _In_        DWORD        nOutBufferSize,
         _Out_opt_   LPDWORD      lpBytesReturned,
         _Inout_opt_ LPOVERLAPPED lpOverlapped
        )
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
			logmsg << hexdump(lpOutBuffer,
			                  lpBytesReturned ? *lpBytesReturned : nOutBufferSize);
		}
		logmsg << "=================" << std::endl;
	} else {
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
	ADD_HOOK(SetupDiGetDeviceInterfaceDetailA);
	ADD_HOOK(SetupDiGetDeviceInterfaceDetailW);
	ADD_HOOK(SetupDiEnumDeviceInterfaces);
	ADD_HOOK(SetupDiGetDevicePropertyW);
	ADD_HOOK(RegisterDeviceNotificationW);
	ADD_HOOK(SetupDiGetDeviceRegistryProperty);
	ADD_HOOK(DeviceIoControl);

	LOGI << "Installed hooks.";
}
