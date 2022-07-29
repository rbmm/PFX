#include "stdafx.h"

_NT_BEGIN

#include "asn1.h"

struct SC
{
	BCRYPT_RSAKEY_BLOB* prkb = 0;
	PCWSTR pcszPassword;
	SECURITY_STATUS opStatus = STATUS_NOT_FOUND;
	ULONG cbData;

	SC(PCWSTR pcszPassword) : pcszPassword(pcszPassword)
	{
	}

	~SC()
	{
		delete [] prkb;
	}

	BOOLEAN ImportKey(PUCHAR pb, ULONG cb);

	LPCBYTE GetPriv8Key(LPCBYTE pbBuffer, ULONG cbLength);
};

BOOLEAN SC::ImportKey(PUCHAR pb, ULONG cb)
{
	if (prkb)
	{
		opStatus = RPC_NT_ENTRY_ALREADY_EXISTS;
		return FALSE;
	}

	NCRYPT_PROV_HANDLE hProvider;
	SECURITY_STATUS status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);

	if (!status)
	{
		PCWSTR pcsz = pcszPassword;

		NCryptBuffer buf = { 
			(1 + (ULONG)wcslen(pcsz)) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_SECRET, const_cast<PWSTR>(pcsz) 
		};

		NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, 1, &buf };

		NCRYPT_KEY_HANDLE hKey;

		status = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 
			&ParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

		NCryptFreeObject(hProvider);

		if (!status)
		{
			static const ULONG flags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

			if (!(status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&flags, sizeof(flags), 0)) &&
				!(status = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG)))
			{
				pb = 0, cb = 0;

				while(!(status = NCryptExportKey(hKey, 0, BCRYPT_RSAPRIVATE_BLOB, 0, pb, cb, &cb, 0)))
				{
					if (pb)
					{
						prkb = (BCRYPT_RSAKEY_BLOB*)pb, cbData = cb;
						break;
					}

					if (!(pb = new UCHAR[cb]))
					{
						break;
					}
				}
			}

			NCryptFreeObject(hKey);
		}
	}

	opStatus = status;

	return !status;
}

LPCBYTE SC::GetPriv8Key(LPCBYTE pbBuffer, ULONG cbLength)
{
	bool bDecrypt = false;

	while (cbLength--)
	{
		LPCBYTE pb = pbBuffer;
		ULONG cb = cbLength+1;

		union {
			ULONG uTag;
			char bTag[4];
			struct {
				BYTE tag : 5;
				BYTE type : 1;
				BYTE cls : 2;
			};
		};

		uTag = *pbBuffer++;

		if (tag == 0x1F)
		{
			char c;

			if (!cbLength--)
			{
				return 0;
			}

			bTag[1] = c = *pbBuffer++;

			if (0 > c)
			{
				if (!cbLength--)
				{
					return 0;
				}

				bTag[2] = c = *pbBuffer++;

				if (0 > c)
				{
					if (!cbLength--)
					{
						return 0;
					}

					bTag[3] = c = *pbBuffer++;

					if (0 > c)
					{
						return 0;
					}
				}
			}
		}

		if (!uTag)
		{
			break;
		}

		if (!cbLength--)
		{
			return 0;
		}

		union {
			char len;
			ULONG Len;
			char b[4];
		};

		Len = *pbBuffer++;

		if (0 > len)
		{
			if ((Len &= ~0x80) > cbLength)
			{
				return 0;
			}

			cbLength -= Len;

			switch (len)
			{
			case 4:
				b[3] = *pbBuffer++;
				b[2] = *pbBuffer++;
				b[1] = *pbBuffer++;
				b[0] = *pbBuffer++;
				break;
			case 2:
				b[1] = *pbBuffer++;
				b[0] = *pbBuffer++;
				break;
			case 1:
				b[0] = *pbBuffer++;
				break;
			case 0:
				break;
			default: return 0;
			}
		}

		if (Len > cbLength)
		{
			return 0;
		}

		if (bDecrypt)
		{
			bDecrypt = FALSE;

			if (!ImportKey(const_cast<PUCHAR>(pbBuffer), Len))
			{
				return 0;
			}
		}

		ULONG cbStructInfo;
		union {
			PVOID pvStructInfo;
			PSTR* ppszObjId;
		};

		switch (uTag)
		{
		case ASN_TAG(ctUniversal, pcPrimitive, utObjectIdentifer):
			if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
				pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, &ppszObjId, &cbStructInfo))
			{
				bDecrypt = !strcmp(*ppszObjId, "1.2.840.113549.1.12.10.1.2");

				LocalFree(ppszObjId);
			}
			break;

		case ASN_TAG(ctUniversal, pcPrimitive, utOctetString):
			if (Len > 32)
			{
				GetPriv8Key(pbBuffer, Len);
			}
			break;
		}

		if (type)
		{
			if (Len)
			{
				if (!GetPriv8Key(pbBuffer, Len)) return 0;
			}
		}

		cbLength -= Len, pbBuffer += Len;
	}

	return pbBuffer;
}

HRESULT PFXImport(_In_ PUCHAR pbPFX, 
				  _In_ ULONG cbPFX, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PDATA_BLOB pRsaKey, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	SC sc(szPassword);
	if (!sc.GetPriv8Key(pbPFX, cbPFX) )
	{
		return OSS_DATA_ERROR;
	}

	if (sc.opStatus)
	{
		return HRESULT_FROM_WIN32(sc.opStatus);
	}

	DATA_BLOB pfx = { cbPFX, pbPFX };

	if (HCERTSTORE hStore = PFXImportCertStore(&pfx, szPassword, PKCS12_ONLY_CERTIFICATES|PKCS12_ALWAYS_CNG_KSP|PKCS12_NO_PERSIST_KEY))
	{
		PCCERT_CONTEXT pCertContext = 0;

		while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext))
		{
			BOOL b = FALSE;
			ULONG cb;
			BCRYPT_RSAKEY_BLOB* prkb;

			PCRYPT_BIT_BLOB PublicKey = &pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey;
			if (CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, 
				PublicKey->pbData, PublicKey->cbData, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 
				0, &prkb, &cb))
			{
				b = cb > sizeof(BCRYPT_RSAKEY_BLOB) &&
					prkb->BitLength == sc.prkb->BitLength &&
					!memcmp(prkb + 1, sc.prkb + 1, cb - sizeof(BCRYPT_RSAKEY_BLOB));

				LocalFree(prkb);
			}

			if (b)
			{
				break;
			}
		}

		CertCloseStore(hStore, 0);

		if (pCertContext)
		{
			*ppCertContext = pCertContext;
			pRsaKey->pbData = (PUCHAR)sc.prkb, sc.prkb = 0;
			pRsaKey->cbData = sc.cbData;

			return S_OK;
		}

		return HRESULT_FROM_NT(STATUS_NOT_FOUND);
	}

	return HRESULT_FROM_WIN32(GetLastError());
}

HRESULT GetLastErrorEx(ULONG dwError = GetLastError())
{
	NTSTATUS status = RtlGetLastNtStatus();
	return dwError == RtlNtStatusToDosErrorNoTeb(status) ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _Out_ PDATA_BLOB pRsaKey, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	HANDLE hFile = CreateFileW(lpFileName, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	if (!hFile)
	{
		return GetLastErrorEx();
	}

	ULONG f = FACILITY_NT_BIT;

	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);

	if (0 <= status)
	{
		if (fsi.EndOfFile.QuadPart - 0x100 > MAXUSHORT)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PUCHAR pbPFX = new UCHAR [fsi.EndOfFile.LowPart])
			{
				if (0 <= (status = NtReadFile(hFile, 0, 0, 0, &iosb, pbPFX, fsi.EndOfFile.LowPart, 0, 0)))
				{
					f = 0;
					status = PFXImport(pbPFX, (ULONG)iosb.Information, szPassword, pRsaKey, ppCertContext);
				}

				delete [] pbPFX;
			}
		}
	}

	NtClose(hFile);

	return status ? status | f : S_OK;
}

ULONG SizeTLV(TLV* tlv)
{
	ULONG cbData = 0, cbLen, Len;

	do 
	{
		ULONG cbTag = 1;

		if (tlv->u.tag == 0x1f)
		{
			cbTag = 2;
			if (tlv->u.bTag[1] < 0)
			{
				cbTag = 3;
				if (tlv->u.bTag[2] < 0)
				{
					cbTag = 4;
					if (tlv->u.bTag[3] < 0)
					{
						return 0;
					}
				}
			}
		}

		if (tlv->u.type)
		{
			if (!tlv->child || tlv->Len || !(Len = SizeTLV(tlv->child)))
			{
				return 0;
			}
			tlv->Len = Len;
		}
		else
		{
			Len = tlv->Len;
		}

		if (Len < 0x80)
		{
			cbLen = 1;
		}
		else if (Len < 0x100)
		{
			cbLen = 2;
		}
		else if (Len < 0x10000)
		{
			cbLen = 3;
		}
		else
		{
			cbLen = 5;
		}

		cbData += cbTag + cbLen + Len;

	} while (tlv = tlv->next);

	return cbData;
}

PBYTE PackTLV(TLV* tlv, PBYTE pb)
{
	do 
	{
		union {
			ULONG uTag;
			char bTag[4];
			struct {
				BYTE tag : 5;
				BYTE type : 1;
				BYTE cls : 2;
			};
		};

		uTag = tlv->u.uTag;

		*pb++ = bTag[0];

		if (tag == 0x1f)
		{
			char c;

			*pb++ = c = bTag[1];

			if (0 > c)
			{
				*pb++ = c = bTag[2];

				if (0 > c)
				{
					*pb++ = c = bTag[3];

					if (0 > c)
					{
						return 0;
					}
				}
			}
		}

		union {
			ULONG Len;
			char b[4];
		};

		Len = tlv->Len;

		if (Len < 0x80)
		{
			*pb++ = b[0];
		}
		else if (Len < 0x100)
		{
			*pb++ = 0x81;
			*pb++ = b[0];
		}
		else if (Len < 0x10000)
		{
			*pb++ = 0x82;
			*pb++ = b[1];
			*pb++ = b[0];
		}
		else
		{
			*pb++ = 0x84;
			*pb++ = b[3];
			*pb++ = b[2];
			*pb++ = b[1];
			*pb++ = b[0];
		}

		if (tlv->u.type)
		{
			pb = PackTLV(tlv->child, pb);
		}
		else if (Len)
		{
			memcpy(pb, tlv->pvData, Len);
			pb += Len;
		}

	} while (tlv = tlv->next);

	return pb;
}

_NT_END