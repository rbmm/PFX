#pragma once

NTSTATUS CreateContainer(_Out_ PHANDLE phFile, _In_ ULONG DeviceNumber, _Out_ PWSTR szVolume, _In_ ULONG cchVolume);

struct CDisk;

class DiskList : LIST_ENTRY 
{
	ULONG _cItems = 0, _dwSelectedItem = MAXULONG;

	CDisk* GetDisk(ULONG dwItem);

	void EnumDisks(_In_ HWND hwndCB);

public:

	DiskList()
	{
		InitializeListHead(this);
	}

	~DiskList();

	HDEVNOTIFY Init(_In_ HWND hwndCB, _In_ HWND hwndMy);
	
	void Add(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface);
	
	void Remove(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface);

	void OnInterfaceChange(_In_ HWND hwndCB, WPARAM wParam, PDEV_BROADCAST_DEVICEINTERFACE p);

	int GetDeviceNumber(_In_ ULONG dwItem, _Out_ UCHAR SerialMD5[]);

	PCWSTR GetDiskName(_In_ ULONG dwItem);

	int GetSelectedDeviceNumber(_Out_ UCHAR SerialMD5[])
	{
		return GetDeviceNumber(_dwSelectedItem, SerialMD5);
	}

	HRESULT SetSelectedValue(ULONG dwSelectedItem)
	{
		return dwSelectedItem < _cItems ? _dwSelectedItem = dwSelectedItem, S_OK : E_INVALIDARG;
	}

	HRESULT GetValueCount(ULONG *pcItems, ULONG *pdwSelectedItem)
	{
		*pcItems = _cItems, *pdwSelectedItem = _dwSelectedItem;
		return S_OK;
	}

	HRESULT GetComboBoxValueAt(ULONG dwItem, PWSTR *ppszItem);
};