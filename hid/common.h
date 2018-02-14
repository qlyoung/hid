#pragma once

#define logfilename "hid.log"

void mLog(const char *message);
extern HMODULE hid;

/*
 * Redefine structure here so I don't have to include hidsdi.h, which defines
 * the HidD_* functions resulting in linker errors because I define these
 * functions elsewhere in the project.
 */
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
typedef BOOL(WINAPI *DeviceIoControl_t)(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

/* Proxied HID functions */
extern HidD_GetAttributes_t real_HidD_GetAttributes;
extern HidD_GetManufacturerString_t real_HidD_GetManufacturerString;
extern HidD_GetSerialNumberString_t real_HidD_GetSerialNumberString;
extern HidD_GetProductString_t real_HidD_GetProductString;
extern HidD_GetHidGuid_t real_HidD_GetHidGuid;
extern HidD_SetFeature_t real_HidD_SetFeature;

/* ioctl hook */
extern DeviceIoControl_t hook_DeviceIoControl;