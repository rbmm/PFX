#include "stdafx.h"
#include "resource.h"

_NT_BEGIN

#include "../inc/initterm.h"
#include "disk.h"
#include "card.h"

#define MD5_HASH_SIZE 16

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PDATA_BLOB pRsaKey, 
				  _Out_ PCCERT_CONTEXT* ppCertContext);

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = -1;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

class PfxDlg : public ZDlg, DiskList
{
	PCWSTR _pcszUPN;
	HDEVNOTIFY _HandleV = 0;
	HICON _hi;
	WCHAR _psc;
	bool _bDiskOk = false, _bOK = false;

	void CheckDisk(HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDOK), 0 <= ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1)));
	}

	HRESULT OnOk(HWND hwndDlg, PCWSTR lpFileName, PCWSTR szPassword, UCHAR SerialMD5[], void** ppvBag, ULONG* pcbBag)
	{
		DATA_BLOB rsa2 {};
		PCCERT_CONTEXT pCertContext = 0;
		HRESULT hr = PFXImport(lpFileName, szPassword, &rsa2, &pCertContext);

		if (0 <= hr)
		{
			if (0 <= (hr = IsKeySupported((BCRYPT_RSAKEY_BLOB*)rsa2.pbData)))
			{
				BOOL b;
				CRYPTUI_VIEWCERTIFICATE_STRUCT cvi = { sizeof(cvi), hwndDlg, 
					CRYPTUI_DISABLE_ADDTOSTORE|CRYPTUI_DISABLE_EDITPROPERTIES|CRYPTUI_DISABLE_EXPORT,
					L"Write Certificate to Card ?", pCertContext
				};

				hr = CryptUIDlgViewCertificateW(&cvi, &b) 
					? CreateSafeBag(ppvBag, pcbBag, pCertContext, 
					(BCRYPT_RSAKEY_BLOB*)rsa2.pbData, rsa2.cbData, SerialMD5, "0", 1)
					: HRESULT_FROM_WIN32(ERROR_CANCELLED);

				CertFreeCertificateContext(pCertContext);
			}

			LocalFree(rsa2.pbData);
		}

		return hr;
	}

	inline static UINT E_id[] = { IDC_EDIT1, IDC_EDIT2, IDC_EDIT3, IDC_EDIT4 };

	static BOOL IsBadPin(PCSTR apin, PCWSTR wpin)
	{
		CHAR pin[0x40];

		return !WideCharToMultiByte(CP_OEMCP, 0, wpin, MAXULONG, pin, _countof(pin), 0, 0) || strcmp(pin, apin);
	}

	void OnOk(HWND hwndDlg)
	{
		UCHAR SerialMD5[MD5_HASH_SIZE];
		int iDisk, DeviceNumber = -1;

		if (0 > (iDisk = ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1))) ||
			0 > (DeviceNumber = GetDeviceNumber(iDisk, SerialMD5)))
		{
			ShowErrorBox(hwndDlg, STATUS_VOLMGR_DISK_MISSING, L"Select Disk Drive", MB_ICONWARNING);
			return ;
		}

		PWSTR psz[_countof(E_id)] {};

		ULONG i = _countof(E_id);

		HWND hwndEdit;

		do 
		{
			if (ULONG len = GetWindowTextLengthW(hwndEdit = GetDlgItem(hwndDlg, E_id[--i])))
			{
				if (len - 1 < MAXSHORT)
				{
					++len;
					GetWindowTextW(hwndEdit, psz[i] = (PWSTR)alloca(len * sizeof(WCHAR)), len);
				}
			}
		} while (i);

		if (!psz[2])
		{
			ShowErrorBox(hwndDlg, STATUS_PWD_TOO_SHORT, L"Empty PIN", MB_ICONWARNING);
			return ;
		}

		if (wcslen(psz[2]) >= 0x3f)
		{
			ShowErrorBox(hwndDlg, STATUS_PWD_TOO_LONG, L"Too long PIN", MB_ICONWARNING);
			return ;
		}

		CHAR pin[0x40];
		if (!WideCharToMultiByte(CP_UTF8, 0, psz[2], MAXULONG, pin, _countof(pin), 0, 0))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
			return ;
		}

		if (!psz[3] || wcscmp(psz[2], psz[3]))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_NOT_SAME_OBJECT), L"PINs not match !", MB_ICONWARNING);
			return ;
		}

		if (IsBadPin(pin, psz[3]))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
			return ;
		}

		PVOID pvSafeBag;
		ULONG cbSafeBag;

		HRESULT hr = OnOk( hwndDlg, psz[0], psz[1] ? psz[1] : L"", SerialMD5, &pvSafeBag, &cbSafeBag);

		if (0 <= hr)
		{
			WCHAR sz[0x200] = L"\\device\\{558C15DD-3EE2-4f78-9664-522382134DE3}";
			ULONG cch = (ULONG)wcslen(sz);

			HANDLE hFile;
			if (0 <= (hr = CreateContainer(&hFile, DeviceNumber, sz + cch, _countof(sz) - cch)))
			{
				IO_STATUS_BLOCK iosb;
				hr = NtWriteFile(hFile, 0, 0, 0, &iosb, pvSafeBag, cbSafeBag, 0, 0);
				NtClose(hFile);

				if (GetTickCount())
				{
					UNICODE_STRING ObjectName;
					OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
					RtlInitUnicodeString(&ObjectName, sz);
					if (0 <= NtOpenFile(&oa.RootDirectory, SYNCHRONIZE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_ALERT))
					{
						NtClose(oa.RootDirectory);
					}
				}
			}

			LocalFree(pvSafeBag);
		}

		ShowErrorBox(hwndDlg, hr, L"Import PFX", MB_ICONINFORMATION);
	}

	static void OnBrowse(HWND hwndDlg)
	{
		IFileOpenDialog *pFileOpen;

		HRESULT hr = CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV(pFileOpen));

		if (SUCCEEDED(hr))
		{
			pFileOpen->SetOptions(FOS_NOVALIDATE|FOS_NOTESTFILECREATE|
				FOS_NODEREFERENCELINKS|FOS_DONTADDTORECENT|FOS_FORCESHOWHIDDEN);

			static const COMDLG_FILTERSPEC rgSpec[] =
			{ 
				{ L"PKCS#12 Files", L"*.pfx;*.p12" },
				{ L"All files", L"*" },
			};

			if (0 <= (hr = pFileOpen->SetFileTypes(_countof(rgSpec), rgSpec)) && 
				0 <= (hr = pFileOpen->SetFileTypeIndex(0)) && 
				0 <= (hr = pFileOpen->Show(hwndDlg)))
			{
				IShellItem *pItem;
				hr = pFileOpen->GetResult(&pItem);

				if (SUCCEEDED(hr))
				{
					PWSTR pszFilePath;
					hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

					if (SUCCEEDED(hr))
					{
						SetDlgItemTextW(hwndDlg, IDC_EDIT1, pszFilePath);
						CoTaskMemFree(pszFilePath);
					}
					pItem->Release();
				}
			}
			pFileOpen->Release();
		}
	}

	void OnInitDialog(HWND hwndDlg)
	{
		HDEVNOTIFY HandleV = Init(GetDlgItem(hwndDlg, IDC_COMBO1), hwndDlg);
		if (!HandleV)
		{
			EndDialog(hwndDlg, IDCANCEL);
			return;
		}

		_HandleV = HandleV;
		CheckDisk(hwndDlg);

		if (HICON hi = LoadIconW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(1)))
		{
			_hi = hi;
			SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hi);
		}

		static const PCWSTR ss[] = {
			L"Specify the file you want to import.",
			L"Type the password for the private key.",
			L"Enter PIN",
			L"Confirm PIN"
		};

		ULONG n = _countof(E_id);
		do 
		{
			--n;
			SendDlgItemMessage(hwndDlg, E_id[n], EM_SETCUEBANNER, FALSE, (LPARAM)ss[n]);
		} while (n);

		_psc = (WCHAR)SendDlgItemMessage(hwndDlg, IDC_EDIT2, EM_GETPASSWORDCHAR, 0, 0);

		SetFocus(GetDlgItem(hwndDlg, IDC_BUTTON1));
	}

	void TooglePasswordChar(HWND hwndDlg, HWND hwndCheck, UINT id, UINT id2 = 0)
	{
		WCHAR c = SendMessageW(hwndCheck, BM_GETCHECK, 0, 0) == BST_CHECKED ? 0 : _psc;

		do 
		{
			if (hwndCheck = GetDlgItem(hwndDlg, id))
			{
				SendMessageW(hwndCheck, EM_SETPASSWORDCHAR, c, 0);
				InvalidateRect(hwndCheck, 0, FALSE);
			}

		} while ((id != id2) && (id = id2));
	}

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;

			case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
				OnBrowse(hwndDlg);
				break;

			case MAKEWPARAM(IDOK, BN_CLICKED):
				OnOk(hwndDlg);
				break;

			case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT2);
				break;

			case MAKEWPARAM(IDC_CHECK2, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT3, IDC_EDIT4);
				break;
			}
			return 0;

		case WM_INITDIALOG:
			OnInitDialog(hwndDlg);
			break;

		case WM_DESTROY:
			if (HICON hi = _hi) DestroyIcon(hi);
			if (HDEVNOTIFY HandleV = _HandleV) UnregisterDeviceNotification(HandleV);
			break;

		case WM_DEVICECHANGE:
			OnInterfaceChange(GetDlgItem(hwndDlg, IDC_COMBO1), wParam, reinterpret_cast<PDEV_BROADCAST_DEVICEINTERFACE>(lParam));
			CheckDisk(hwndDlg);
			return 0;

		case WM_CTLCOLOREDIT:
			SetBkColor((HDC)wParam, GetSysColor(COLOR_WINDOW));
			SetBkMode((HDC)wParam, TRANSPARENT);
			[[fallthrough]];
		case WM_CTLCOLORDLG:
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_CTLCOLORSTATIC:
			SetTextColor((HDC)wParam, (INT_PTR)GetSysColor(COLOR_WINDOWTEXT));
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_PAINT:
			PAINTSTRUCT ps;
			if (BeginPaint(hwndDlg, &ps))
			{
				RECT rc;
				GetWindowRect(GetDlgItem(hwndDlg, IDOK), &rc);
				MapWindowRect(0, hwndDlg, &rc);
				
				GetClientRect(hwndDlg, &ps.rcPaint);
				ps.rcPaint.top = rc.top - (ps.rcPaint.bottom - rc.bottom);
				FillRect(ps.hdc, &ps.rcPaint, GetSysColorBrush(COLOR_MENU));
				EndPaint(hwndDlg, &ps);
			}
			return TRUE;
		}

		return __super::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}
};

void WINAPI ep(void*)
{
	initterm();
	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		PfxDlg dlg;
		dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, 0);

		CoUninitialize();
	}

	destroyterm();
	ExitProcess(0);
}

_NT_END