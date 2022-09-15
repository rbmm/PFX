#include "stdafx.h"

#define ZLIB_INTERNAL
#include "../zlib/zlib.h"

_NT_BEGIN

#include "asn1.h"
#include "card.h"

#define MD5_HASH_SIZE 16

NTSTATUS CreateHash(_Out_ BCRYPT_HASH_HANDLE *phHash, _In_ PCWSTR pszAlgId)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		status = BCryptCreateHash(hAlgorithm, phHash, 0, 0, 0, 0, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}
	
	return status;
}

NTSTATUS DoHash(PUCHAR pbData, ULONG cbData, PUCHAR pbOutput, ULONG cbOutput, PCWSTR pszAlgId)
{
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hHash;

	if (0 <= (status = CreateHash(&hHash, pszAlgId)))
	{
		0 <= (status = BCryptHashData(hHash, pbData, cbData, 0)) &&
			0 <= (status = BCryptFinishHash(hHash, pbOutput, cbOutput, 0));

		BCryptDestroyHash(hHash);
	}

	return status;
}

NTSTATUS h_MD5(PUCHAR pbOutput, LPCVOID pbData, ULONG cbData)
{
	return DoHash((PUCHAR)pbData, cbData, pbOutput, 16, BCRYPT_MD5_ALGORITHM);
}

NTSTATUS SymKeyFromPin(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PBYTE pbPin, _In_ ULONG cbPin, _In_ UCHAR SerialMD5[])
{
	if (!cbPin)
	{
		return STATUS_BAD_DATA;
	}

	UCHAR PinMD5[16];
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status = h_MD5(PinMD5, pbPin, cbPin);

	if (0 <= status &&
		0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;

		if (0 <= (status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, SerialMD5, MD5_HASH_SIZE, 0)))
		{
			status = BCryptEncrypt(hKey, PinMD5, sizeof(PinMD5), 0, 0, 0, PinMD5, sizeof(PinMD5), &cbPin, 0);

			BCryptDestroyKey(hKey);

			if (0 <= status)
			{
				status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, PinMD5, sizeof(PinMD5), 0);
			}
		}

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}


enum SCAlgId : UCHAR { 
	GIDS_INVALID,
	GIDS_RSA_1024_IDENTIFIER = 0x06,
	GIDS_RSA_2048_IDENTIFIER,
	// Unsupported key algorithm ids:
	//GIDS_RSA_3072_IDENTIFIER,
	//GIDS_RSA_4096_IDENTIFIER,
	//GIDS_ECC_192_IDENTIFIER,
	//GIDS_ECC_224_IDENTIFIER,
	//GIDS_ECC_256_IDENTIFIER,
	//GIDS_ECC_384_IDENTIFIER,
	//GIDS_ECC_521_IDENTIFIER,
};

struct SC_Container
{
	enum : UCHAR { scTag = '#' } Tag;
	SCAlgId algid;
	USHORT PrivKeyLength, PubKeyLength, CertLength;
	UCHAR MD5[16], cardid[16];
	UCHAR buf[];//AES128(pin & serial)(PrivKey)+PubKey+Cert+SIG

	SCAlgId FromKeySize(BCRYPT_RSAKEY_BLOB* pvrkb)
	{
		switch (pvrkb->BitLength)
		{
		case 1024:
			return GIDS_RSA_1024_IDENTIFIER;
		case 2048:
			return GIDS_RSA_2048_IDENTIFIER;
		}
		return GIDS_INVALID;
	}

	void* operator new(size_t cb, ULONG ex)
	{
		return LocalAlloc(0, cb + ex);
	}

	void operator delete(void* pv)
	{
		LocalFree(pv);
	}

	PBYTE GetPrivKey()
	{
		return buf;
	}

	PBYTE GetPubKey()
	{
		return GetPrivKey() + PrivKeyLength;
	}

	PBYTE GetCert()
	{
		return GetPubKey() + PubKeyLength;
	}

	ULONG GetSize(ULONG* pKeySize)
	{
		ULONG KeySize = 0x80;

		switch (algid)
		{
		case GIDS_RSA_2048_IDENTIFIER:
			KeySize = 0x100;
			[[fallthrough]];
		case GIDS_RSA_1024_IDENTIFIER:
			*pKeySize = KeySize;
			return sizeof(SC_Container) + PrivKeyLength + PubKeyLength + CertLength + KeySize;
		}

		return 0;
	}

	NTSTATUS CreateSafeBag(
		_In_ LPCBYTE pbCertEncoded, 
		_In_ ULONG cbCertEncoded, 
		_In_ BCRYPT_RSAKEY_BLOB* prkb,
		_In_ ULONG cbKey,
		_In_ ULONG cbFree,
		_In_ UCHAR SerialMD5[],
		_In_ PCSTR pin, 
		_In_ ULONG pinLen);
};

C_ASSERT(sizeof(SC_Container) == FIELD_OFFSET(SC_Container, buf));

PBYTE PackPubKey(BCRYPT_RSAKEY_BLOB* pvrkb, PBYTE pb, PULONG pcbFree, PUSHORT psize)
{
	ULONG cb = *pcbFree, cbPublicExp = pvrkb->cbPublicExp, cbModulus = pvrkb->cbModulus;
	Asn1Alloc aa(pb, cb);

	if (aa.Store(0x82, cbPublicExp, ++pvrkb, cbPublicExp) && 
		aa.Store(0x81, cbModulus, (PBYTE)pvrkb + cbPublicExp, cbModulus) &&
		aa.Store(0x497f, cb - aa.FreeSize()))
	{
		memcpy(pb, aa.GetBuf(), cb -= aa.FreeSize());

		*pcbFree -= cb;
		*psize = (USHORT)cb;
		return pb + cb;
	}

	return 0;
}

NTSTATUS PackCert(const BYTE* pbCertEncoded, ULONG cbCertEncoded, PBYTE buf, ULONG cbFree, PUSHORT psize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (ULONG cb = compressBound(cbCertEncoded))
	{
		if (PBYTE pb = new BYTE[4 + cb])
		{
			if (compress(pb + 4, &cb, pbCertEncoded, cbCertEncoded) == Z_OK)
			{
				*(PUSHORT)pb = 'KC';
				*(1 + (PUSHORT)pb) = (USHORT)cbCertEncoded;

				if (StoreSingleTag(0x70DF, pb, cb + 4, buf, cbFree, &cb))
				{
					*psize = (USHORT)cb;
					status = STATUS_SUCCESS;
				}
			}

			delete[] pb;
		}
	}

	return status;
}

NTSTATUS DataToKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PUCHAR pb, _In_ ULONG cb)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, 0, 0)))
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_RSAPRIVATE_BLOB, phKey, pb, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS
SignHash(
		 _In_ BCRYPT_RSAKEY_BLOB* prkb,
		 _In_ ULONG cbKey,
		 _In_ PUCHAR pbInput,
		 _In_ ULONG cbInput,
		 _Out_ PUCHAR pbOutput,
		 _In_ ULONG cbOutput,
		 _Out_ ULONG *pcbResult)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = DataToKey(&hKey, (PBYTE)prkb, cbKey)))
	{
		BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_MD5_ALGORITHM };

		status = BCryptSignHash(hKey, &pi, pbInput, cbInput, pbOutput, cbOutput, pcbResult, BCRYPT_PAD_PKCS1);

		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS SC_Container::CreateSafeBag(
	_In_ LPCBYTE pbCertEncoded, 
	_In_ ULONG cbCertEncoded, 
	_In_ BCRYPT_RSAKEY_BLOB* prkb,
	_In_ ULONG cbKey,
	_In_ ULONG cbFree,
	_In_ UCHAR SerialMD5[],
	_In_ PCSTR pin, 
	_In_ ULONG pinLen
	)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hSymKey;
	ULONG cb;
	PBYTE pb = buf;

	if (0 <= (status = BCryptGenRandom(0, cardid, sizeof(cardid), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
		0 <= (status = SymKeyFromPin(&hSymKey, (PBYTE)pin, pinLen, SerialMD5)))
	{
		status = BCryptEncrypt(hSymKey, (PUCHAR)prkb, cbKey, 0, 0, 0, pb, cbFree, &cb, BCRYPT_BLOCK_PADDING);

		BCryptDestroyKey(hSymKey);

		if (0 <= status)
		{
			pb += cb, cbFree -= cb, PrivKeyLength = (USHORT)cb;

			status = STATUS_UNSUCCESSFUL;

			if (pb = PackPubKey(prkb, pb, &cbFree, &PubKeyLength))
			{
				memcpy(MD5, SerialMD5, MD5_HASH_SIZE);
				Tag = scTag;
				algid = FromKeySize(prkb);

				if (0 <= (status = PackCert(pbCertEncoded, cbCertEncoded, pb, cbFree, &CertLength)) &&
					0 <= (status = h_MD5(MD5, (PBYTE)this, RtlPointerToOffset(this, pb += CertLength))) &&
					0 <= (status = SignHash(prkb, cbKey, MD5, sizeof(MD5), pb, cbFree, &cb)))
				{
					if (cb != prkb->cbModulus)
					{
						status = STATUS_INTERNAL_ERROR;
					}
				}
			}
		}
	}

	return status;
}

NTSTATUS IsKeySupported(_In_ BCRYPT_RSAKEY_BLOB* prkb)
{
	if (prkb->Magic == BCRYPT_RSAPRIVATE_MAGIC)
	{
		switch (prkb->BitLength)
		{
		case 1024:
		case 2048:
			return prkb->cbPublicExp < 3 ? STATUS_TPM_20_E_ASYMMETRIC : STATUS_SUCCESS;
		}

		return STATUS_TPM_20_E_KEY_SIZE;
	}

	return STATUS_TPM_20_E_ASYMMETRIC;
}

NTSTATUS CreateSafeBag(
					   _Out_ void** ppvBag,
					   _Out_ ULONG* pcbBag,
					   _In_ PCCERT_CONTEXT pCertContext, 
					   _In_ BCRYPT_RSAKEY_BLOB* prkb,
					   _In_ ULONG cbKey,
					   _In_ UCHAR SerialMD5[],
					   _In_ PCSTR pin, 
					   _In_ ULONG pinLen
					   )
{
	NTSTATUS status = IsKeySupported(prkb);

	if (0 > status)
	{
		return status;
	}

	if (SC_Container* p = new(MINSHORT) SC_Container)
	{
		if (0 <= (status = p->CreateSafeBag(
			pCertContext->pbCertEncoded, pCertContext->cbCertEncoded,
			prkb, cbKey, MINSHORT, SerialMD5, pin, pinLen)))
		{
			*ppvBag = p, *pcbBag = p->GetSize(&cbKey);
			
			return STATUS_SUCCESS;
		}

		delete p;

		return status;
	}

	return STATUS_NO_MEMORY;
}

_NT_END