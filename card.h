#pragma once

NTSTATUS IsKeySupported(_In_ BCRYPT_RSAKEY_BLOB* prkb);

NTSTATUS CreateSafeBag(
					   _Out_ void** ppvBag,
					   _Out_ ULONG* pcbBag,
					   _In_ PCCERT_CONTEXT pCertContext, 
					   _In_ BCRYPT_RSAKEY_BLOB* prkb,
					   _In_ ULONG cbKey,
					   _In_ UCHAR SerialMD5[],
					   _In_ PCSTR pin, 
					   _In_ ULONG pinLen
					   );
