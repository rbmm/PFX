#include "stdafx.h"

_NT_BEGIN

#include <initguid.h>
#include <ntddstor.h>
#include "disk.h"
#include <initguid.h>
#include <devpkey.h>

extern const volatile UCHAR guz = 0;

NTSTATUS h_MD5(PUCHAR pbOutput, LPCVOID pbData, ULONG cbData);

HRESULT CoStrDup(_In_ PCWSTR psz, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
	*ppwsz = 0;

	if (!psz) return E_INVALIDARG;

	SIZE_T cb = (wcslen(psz) + 1) * sizeof(WCHAR);

	if (PVOID pv = CoTaskMemAlloc(cb))
	{
		memcpy(pv, psz, cb);
		*ppwsz = (PWSTR)pv;

		return S_OK;
	}

	return E_OUTOFMEMORY;
}

struct __declspec(novtable) CInterfaceList 
{
	virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface) = 0;

	void Enum(_In_ LPCGUID Guid)
	{
		CONFIGRET cr;
		ULONG cb = 0, rcb;
		union {
			PVOID buf;
			PZZWSTR Buffer;
		};

		PVOID stack = alloca(guz);
		do 
		{
			cr = CM_Get_Device_Interface_List_SizeW(&rcb, const_cast<GUID*>(Guid), 0, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

			if (cr != CR_SUCCESS)
			{
				break;
			}

			if (cb < (rcb *= sizeof(WCHAR)))
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			cr = CM_Get_Device_Interface_ListW(const_cast<GUID*>(Guid), 
				0, Buffer, cb/sizeof(WCHAR), CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

		} while (cr == CR_BUFFER_SMALL);

		if (cr == CR_SUCCESS)
		{
			while (*Buffer && OnInterface(Buffer))
			{
				Buffer += wcslen(Buffer) + 1;
			}
		}
	}
};

CONFIGRET GetFriendlyName(_Out_ PWSTR* ppszName, _In_ DEVINST dnDevInst)
{
	DEVPROPTYPE PropertyType;

	union {
		PVOID pv;
		PWSTR sz;
		PBYTE pb;
	};

	ULONG cb = 0x80;
	CONFIGRET cr;

	do 
	{
		cr = CR_OUT_OF_MEMORY;

		if (pv = LocalAlloc(0, cb))
		{
			if (CR_SUCCESS == (cr = CM_Get_DevNode_PropertyW(dnDevInst, &DEVPKEY_NAME, &PropertyType, pb, &cb, 0)))
			{
				*ppszName = sz;
				return CR_SUCCESS;
			}
			LocalFree(pv);
		}

	} while (cr == CR_BUFFER_SMALL);

	return cr;
}

CONFIGRET GetFriendlyName(_Out_ PWSTR* ppszName, _In_ PCWSTR pszDeviceInterface)
{
	DEVPROPTYPE PropertyType;

	union {
		PBYTE PropertyBuffer;
		PVOID buf;
		PWSTR pszName;
		DEVINSTID_W pDeviceID;
	};

	ULONG cb = 0, rcb = 0x80;
	CONFIGRET cr;
	PVOID stack = alloca(guz);

	do 
	{
		if (cb < rcb)
		{
			rcb = cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		cr = CM_Get_Device_Interface_PropertyW(pszDeviceInterface, 
			&DEVPKEY_Device_InstanceId, &PropertyType, PropertyBuffer, &rcb, 0);

	} while (cr == CR_BUFFER_SMALL);

	if (cr == CR_SUCCESS)
	{
		if (PropertyType != DEVPROP_TYPE_STRING)
		{
			return CR_FAILURE;
		}

		DEVINST dnDevInst;

		if (CR_SUCCESS == (cr = CM_Locate_DevNodeW(&dnDevInst, pDeviceID, CM_LOCATE_DEVNODE_NORMAL)))
		{
			return GetFriendlyName(ppszName, dnDevInst);
		}
	}

	return cr;
}

//////////////////////////////////////////////////////////////////////////

struct CVolumeList : CInterfaceList
{
	PWSTR szVolume;
	ULONG cchVolume;
	ULONG DeviceNumber;
	NTSTATUS opStatus = STATUS_UNRECOGNIZED_MEDIA;

	CVolumeList(ULONG DeviceNumber, PWSTR szVolume, ULONG cchVolume) : DeviceNumber(DeviceNumber), szVolume(szVolume), cchVolume(cchVolume)
	{
	}

	virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface);
};

BOOL CVolumeList::OnInterface(_In_ PWSTR pszDeviceInterface)
{
	if (HANDLE hVolume = fixH(CreateFileW(pszDeviceInterface, 0, FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)))
	{
		STORAGE_DEVICE_NUMBER sdn{};
		IO_STATUS_BLOCK iosb;

		NTSTATUS status = NtDeviceIoControlFile(hVolume, 0, 0, 0, &iosb,
			IOCTL_STORAGE_GET_DEVICE_NUMBER, 0, 0, &sdn, sizeof(sdn));

		NtClose(hVolume);

		if (0 <= status && sdn.DeviceType == FILE_DEVICE_DISK && sdn.DeviceNumber == DeviceNumber && sdn.PartitionNumber)
		{
			pszDeviceInterface[1] = '?';
			opStatus = 0 > swprintf_s(szVolume, cchVolume, L"%s\\{DFA1ECDB-2424-47be-BCA9-FE60E043A304}", 
				pszDeviceInterface) ? STATUS_BUFFER_TOO_SMALL : 0;

			return FALSE;
		}
	}

	return TRUE;
}

NTSTATUS CreateContainer(_Out_ PHANDLE phFile, _In_ ULONG DeviceNumber, _Out_ PWSTR szVolume, _In_ ULONG cchVolume)
{
	CVolumeList f(DeviceNumber, szVolume, cchVolume);

	f.Enum(&GUID_DEVINTERFACE_VOLUME);

	NTSTATUS status = f.opStatus;

	if (status)
	{
		return status;
	}

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	RtlInitUnicodeString(&ObjectName, szVolume);

	if (0 <= NtOpenFile(&hFile, SYNCHRONIZE|FILE_WRITE_ATTRIBUTES, &oa, &iosb, FILE_SHARE_VALID_FLAGS, 
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT))
	{
		static FILE_BASIC_INFORMATION fbi = { {}, {}, {}, {}, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_NORMAL };
		NtSetInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
		NtClose(hFile);
	}

	status = NtCreateFile(phFile, FILE_APPEND_DATA|SYNCHRONIZE|DELETE, &oa, &iosb, 0, 
		FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_READONLY, 0, FILE_OVERWRITE_IF, 
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_OPEN_FOR_BACKUP_INTENT|FILE_OPEN_REPARSE_POINT, 0, 0);

	DbgPrint("CreateContainer(%S)=%x\r\n", szVolume, status);

	*wcsrchr(szVolume, '\\') = 0;

	return status;
}

//////////////////////////////////////////////////////////////////////////
#define MD5_HASH_SIZE 16

struct CDisk : public LIST_ENTRY 
{
	UCHAR SerialMD5[MD5_HASH_SIZE];
	PWSTR _name = 0;
	ULONG _DeviceNumber;
	ULONG _hash = 0;

	~CDisk()
	{
		if (PVOID p = _name)
		{
			delete [] p;
		}
	}

	CDisk(ULONG DeviceNumber) : _DeviceNumber(DeviceNumber)
	{
	}

	CONFIGRET InitName(_In_ PCWSTR pszDeviceInterface)
	{
		UNICODE_STRING String;
		RtlInitUnicodeString(&String, pszDeviceInterface);
		RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &_hash);

		return GetFriendlyName(&_name, pszDeviceInterface);
	}

	BOOL InitName(PCSTR ProductId)
	{
		PWSTR name = 0;
		ULONG cch = 0;
		while (cch = MultiByteToWideChar(CP_ACP, 0, ProductId, 0, name, cch))
		{
			if (name)
			{
				_name = name;
				return TRUE;
			}

			if (!(name = new WCHAR[cch]))
			{
				break;
			}
		}

		return FALSE;
	}

	BOOL InitName2(_In_ PCWSTR pszDeviceInterface)
	{
		if (pszDeviceInterface = wcschr(pszDeviceInterface, '#'))
		{
			if (PWSTR pc = wcschr(++pszDeviceInterface, '#'))
			{
				size_t cch = pc - pszDeviceInterface;
				if (PWSTR name = new WCHAR[cch + 1])
				{
					memcpy(name, pszDeviceInterface, cch * sizeof(WCHAR));
					name[cch] = 0;
					_name = name;

					return TRUE;
				}
			}
		}

		return FALSE;
	}
};

BOOL IsExistPartitions(_In_ HANDLE hDisk)
{
	ULONG cb = 0, rcb = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[4]), d = 4*sizeof(PARTITION_INFORMATION_EX);

	union {
		PVOID buf;
		PDRIVE_LAYOUT_INFORMATION_EX pdli;
	};

	PVOID stack = alloca(guz);

__loop:
	if (cb < rcb)
	{
		cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
	}

	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, 0, 0, pdli, cb);

	switch (status)
	{
	case STATUS_BUFFER_TOO_SMALL:
	case STATUS_INFO_LENGTH_MISMATCH:
	case STATUS_BUFFER_OVERFLOW:
		rcb += d, d <<= 1;
		goto __loop;

	case STATUS_SUCCESS:
		if (ULONG PartitionCount = pdli->PartitionCount)
		{
			PPARTITION_INFORMATION_EX PartitionEntry = pdli->PartitionEntry;
			do 
			{
				if (PartitionEntry->PartitionNumber)
				{
					switch (PartitionEntry->PartitionStyle)
					{							
					case PARTITION_STYLE_GPT:
						return TRUE;
					case PARTITION_STYLE_MBR:
						if (PartitionEntry->Mbr.RecognizedPartition)
						{
							return TRUE;
						}
					}
				}

			} while (PartitionEntry++, --PartitionCount);
		}
		break;
	}

	return status;
}

BOOL OnDiskArrival(_Out_ CDisk** ppDisk, _In_ PCWSTR pszDeviceInterface)
{
	DbgPrint("\r\n====================================\r\n%S\r\n", pszDeviceInterface);

	BOOL fOk = FALSE;

	if (HANDLE hDisk = fixH(CreateFileW(pszDeviceInterface, 0, 
		FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)))
	{
		ULONG cb = 0, rcb, Offset;

		PVOID stack = alloca(guz);
		STORAGE_DEVICE_NUMBER sdn{};
		IO_STATUS_BLOCK iosb;

		NTSTATUS status = NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb,
			IOCTL_STORAGE_GET_DEVICE_NUMBER, 0, 0, &sdn, sizeof(sdn));

		if (0 <= status && sdn.DeviceType == FILE_DEVICE_DISK && !sdn.PartitionNumber)
		{
			static const STORAGE_PROPERTY_QUERY spq = { StorageDeviceProperty, PropertyStandardQuery }; 

			union {
				PVOID buf;
				PSTR psz;
				PSTORAGE_DEVICE_DESCRIPTOR psdd;
			};

			rcb = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 0x200;

__loop:
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			switch (status = (NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb, 
				IOCTL_STORAGE_QUERY_PROPERTY, (void*)&spq, sizeof(spq), buf, cb)))
			{
			case STATUS_SUCCESS:
			case STATUS_BUFFER_OVERFLOW:

				if (psdd->Size > cb)
				{
					rcb = psdd->Size;
					goto __loop;
				}

				if (!psdd->RemovableMedia || !(Offset = psdd->SerialNumberOffset) || !IsExistPartitions(hDisk))
				{
					break;
				}

				if (CDisk* pDisk = new CDisk(sdn.DeviceNumber))
				{
					PCSTR Serial = psz + Offset;

					DbgPrint("Serial=\"%s\"\r\n", Serial);

					if (0 <= h_MD5(pDisk->SerialMD5, Serial, (ULONG)strlen(Serial)))
					{
						if (CR_SUCCESS == pDisk->InitName(pszDeviceInterface))
						{
__ok:
							fOk = TRUE;
							*ppDisk = pDisk;
							break;
						}

						if (Offset = psdd->ProductIdOffset)
						{
							if (pDisk->InitName(psz + Offset))
							{
								goto __ok;
							}
						}

						if (pDisk->InitName2(pszDeviceInterface))
						{
							goto __ok;
						}
					}

					delete pDisk;
				}

				break;
			}
		}

		NtClose(hDisk);
	}

	return fOk;
}

void DiskList::EnumDisks(_In_ HWND hwndCB)
{
	struct CDiskList : public CInterfaceList
	{
		DiskList* List;
		HWND hwndCB;

		virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface)
		{
			List->Add(hwndCB, pszDeviceInterface);
			return TRUE;
		}

		CDiskList(DiskList* List, HWND hwndCB) : List(List), hwndCB(hwndCB)
		{
		}

	} e(this, hwndCB);

	e.Enum(&GUID_DEVINTERFACE_DISK);
}

HDEVNOTIFY DiskList::Init(_In_ HWND hwndCB, _In_ HWND hwndMy)
{
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter = { 
		sizeof(DEV_BROADCAST_DEVICEINTERFACE), DBT_DEVTYP_DEVICEINTERFACE, 0, GUID_DEVINTERFACE_DISK
	};

	HDEVNOTIFY HandleV = RegisterDeviceNotification(hwndMy, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);

	EnumDisks(hwndCB);

	return HandleV;
}

DiskList::~DiskList()
{
	PLIST_ENTRY head = this, entry = head->Blink;
	while (entry != head)
	{
		CDisk* pDisk = static_cast<CDisk*>(entry);
		entry = entry->Blink;
		delete pDisk;
	}
}

CDisk* DiskList::GetDisk(ULONG dwItem)
{
	if (dwItem < _cItems)
	{
		PLIST_ENTRY entry = this;

		do 
		{
			entry = entry->Flink;
		} while (dwItem--);

		return static_cast<CDisk*>(entry);
	}

	return 0;
}

PCWSTR DiskList::GetDiskName(ULONG dwItem)
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		return pDisk->_name;
	}

	return 0;
}

int DiskList::GetDeviceNumber(_In_ ULONG dwItem, _Out_ UCHAR SerialMD5[])
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		memcpy(SerialMD5, pDisk->SerialMD5, MD5_HASH_SIZE);
		return pDisk->_DeviceNumber;
	}

	return -1;
}

HRESULT DiskList::GetComboBoxValueAt(ULONG dwItem, PWSTR *ppszItem)
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		return CoStrDup(pDisk->_name, ppszItem);
	}

	*ppszItem = 0;
	return E_INVALIDARG;
}

void DiskList::Remove(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface)
{
	DbgPrint("REMOVECOMPLETE: %S\r\n", pszDeviceInterface);

	ULONG hash;
	UNICODE_STRING String;
	RtlInitUnicodeString(&String, pszDeviceInterface);
	RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &hash);

	ULONG dwItem = 0;
	PLIST_ENTRY head = this, entry = head;

	while ((entry = entry->Flink) != head)
	{
		if (static_cast<CDisk*>(entry)->_hash == hash)
		{
			_cItems--;
			if (dwItem < _dwSelectedItem || _dwSelectedItem == _cItems)
			{
				_dwSelectedItem--;
			}
			RemoveEntryList(entry);
			delete static_cast<CDisk*>(entry);

			ComboBox_DeleteString(hwndCB, dwItem);
			ComboBox_SetCurSel(hwndCB, _dwSelectedItem);

			return ;
		}

		dwItem++;
	}
}

void DiskList::Add(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface)
{
	CDisk* pDisk;
	if (OnDiskArrival(&pDisk, pszDeviceInterface))
	{
		InsertTailList(this, pDisk);
		_dwSelectedItem = _cItems++;

		ComboBox_AddString(hwndCB, pDisk->_name);
		ComboBox_SetCurSel(hwndCB, _dwSelectedItem);
	}
}

void DiskList::OnInterfaceChange(_In_ HWND hwndCB, _In_ WPARAM wParam, _In_ PDEV_BROADCAST_DEVICEINTERFACE p)
{
	switch (wParam)
	{
	case DBT_DEVICEREMOVECOMPLETE:
	case DBT_DEVICEARRIVAL:
		break;
	default: return;
	}

	if (p->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE && p->dbcc_classguid == GUID_DEVINTERFACE_DISK)
	{
		switch (wParam)
		{
		case DBT_DEVICEREMOVECOMPLETE:
			Remove(hwndCB, p->dbcc_name);
			break;
		case DBT_DEVICEARRIVAL:
			Add(hwndCB, p->dbcc_name);
			break;
		}
	}
}

_NT_END