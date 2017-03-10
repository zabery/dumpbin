#include "PEInfo.h"
#include <ImageHlp.h>
#include <iostream>
#pragma comment(lib, "ImageHlp")

CPEInfo::CPEInfo(LPCWSTR sPath)
{
	m_bPE32 = FALSE;
	m_pDosHeader = NULL;
	m_pNtHeader32 = NULL;
	m_pNtHeader64 = NULL;
	m_pFirstSectHeader = NULL;
	m_pIID = NULL;
	m_pIED = NULL;

	LoadFile(sPath);
}

CPEInfo::~CPEInfo()
{
	::UnmapViewOfFile(m_pvImageBase);
}

//////////////////////////////////////////////////////////////////////////
//		public
//////////////////////////////////////////////////////////////////////////
BOOL CPEInfo::IsPEFile()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pvImageBase;
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	m_pNtHeader32 = PIMAGE_NT_HEADERS32((DWORD64)m_pvImageBase + m_pDosHeader->e_lfanew);
	if (m_pNtHeader32->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	if (m_pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		m_bPE32 = TRUE;
		m_pFirstSectHeader = IMAGE_FIRST_SECTION(m_pNtHeader32);
	}
	else if (m_pNtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		m_bPE32 = FALSE;
		m_pNtHeader64 = PIMAGE_NT_HEADERS64((DWORD64)m_pvImageBase + m_pDosHeader->e_lfanew);
		m_pFirstSectHeader = IMAGE_FIRST_SECTION(m_pNtHeader64);
	}

	return TRUE;
}


void CPEInfo::PrintImportTable()
{
	if (m_bPE32)
		PrintImportTable32();
	else
		PrintImportTable64();
}

void CPEInfo::PrintSections()
{
	std::cout << "Summary" << std::endl;
	WORD nSection;

	if (m_bPE32)
		nSection = m_pNtHeader32->FileHeader.NumberOfSections;
	else
		nSection = m_pNtHeader64->FileHeader.NumberOfSections;

	for (WORD idx = 0; idx < nSection; ++idx)
	{
		PIMAGE_SECTION_HEADER pFirstSectHeader = m_pFirstSectHeader + idx;
		std::cout << "	" << std::hex << pFirstSectHeader->VirtualAddress << " " << pFirstSectHeader->Name << std::endl;
	}
}

void CPEInfo::PrintExportTable()
{
	ULONG uSize;
	m_pIED = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(m_pvImageBase, FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &uSize);
	if (m_pIED == NULL)
		return;

	std::cout << "	" << GetNameByRVA(m_pIED->Name) << std::endl;
	std::cout << "	" << std::hex << m_pIED->Characteristics << " characteristics" << std::endl;
	std::cout << "	" << std::hex << m_pIED->TimeDateStamp << " time date stamp" << std::endl;
	std::cout << "	" << m_pIED->MajorVersion << "." << m_pIED->MinorVersion << " version" << std::endl;
	std::cout << "	" << m_pIED->Base << " ordinal base" << std::endl; 
	std::cout << "	" << m_pIED->NumberOfFunctions << " number of functions" << std::endl; 
	std::cout << "	" << m_pIED->NumberOfNames << " number of names" << std::endl;

	std::cout << "	" << "ordinal hint RVA      name" << std::endl;
	for (DWORD dIdx = 0; dIdx < m_pIED->NumberOfFunctions; ++dIdx)
	{
		DWORD *pNameRva = (DWORD *)(RVA2Offset(m_pIED->AddressOfNames + dIdx * sizeof(DWORD)) + (DWORD64)m_pvImageBase);
		DWORD *pFuncRva = (DWORD *)(RVA2Offset(m_pIED->AddressOfFunctions + dIdx * sizeof(DWORD)) + (DWORD64)m_pvImageBase);
		WORD *pOrdRva = (WORD *)(RVA2Offset(m_pIED->AddressOfNameOrdinals + dIdx * sizeof(WORD)) + (DWORD64)m_pvImageBase);
		std::cout << "	" << std::hex << *pOrdRva << " " << *pFuncRva << " " << std::hex << GetNameByRVA(*pNameRva) << std::endl;
	}
}

//////////////////////////////////////////////////////////////////////////
//		private
//////////////////////////////////////////////////////////////////////////

BOOL CPEInfo::LoadFile(LPCWSTR sPath)
{
	HANDLE hFile = ::CreateFile(sPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	HANDLE hFileMapping = ::CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE)
	{
		::CloseHandle(hFile);
		return FALSE;
	}

	m_pvImageBase = ::MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

	::CloseHandle(hFile);
	::CloseHandle(hFileMapping);
	return TRUE;
}

DWORD64 CPEInfo::GetHeaderSize()
{
	return (DWORD64)m_pFirstSectHeader - (DWORD64)m_pvImageBase;
}

DWORD64 CPEInfo::RVA2Offset(DWORD64 dwRVA)
{
	if (dwRVA < GetHeaderSize())
		return 0;

	WORD nSection; 
	
	if (m_bPE32)
		nSection = m_pNtHeader32->FileHeader.NumberOfSections;
	else
		nSection = m_pNtHeader64->FileHeader.NumberOfSections;

	WORD nRvaIdx = -1;
	for (WORD idx = 0; idx < nSection; ++idx)
	{
		PIMAGE_SECTION_HEADER pFirstSectHeader = m_pFirstSectHeader + idx;

		if (dwRVA >= pFirstSectHeader->VirtualAddress && dwRVA <= pFirstSectHeader->VirtualAddress + pFirstSectHeader->Misc.VirtualSize)
		{
			nRvaIdx = idx;
			break;
		}
	}

	DWORD64 dwSub = dwRVA - (m_pFirstSectHeader + nRvaIdx)->VirtualAddress;
	return (m_pFirstSectHeader + nRvaIdx)->PointerToRawData + dwSub;
}

std::string CPEInfo::GetNameByRVA(DWORD64 dwRVA)
{
	std::string sFuncName;
	DWORD64 dwPos = RVA2Offset(dwRVA) + (DWORD64)m_pvImageBase;

	char *pStart = (char *)dwPos;
	while (*pStart)
	{
		sFuncName += *pStart;
		++pStart;
	}
	return sFuncName;
}

void CPEInfo::PrintImportTable32()
{
	ULONG uSize;
	m_pIID = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(m_pvImageBase, FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &uSize);
	if (m_pIID == NULL)
		return;

	while (m_pIID->FirstThunk)
	{
		std::cout << GetNameByRVA(m_pIID->Name) << std::endl;
		std::cout << "	" << std::hex << m_pIID->FirstThunk << " " << "Import Address Table" << std::endl;
		std::cout << "	" << std::hex << m_pIID->OriginalFirstThunk << " " << "Import Name Table" << std::endl;
		std::cout << "	" << std::hex << m_pIID->TimeDateStamp << " " << "time date stamp" << std::endl;
		std::cout << "	" << std::hex << m_pIID->ForwarderChain << " " << "Index of first forwarder reference" << std::endl;
		
		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(DWORD64(m_pvImageBase) + RVA2Offset(m_pIID->FirstThunk));
		while (pThunk->u1.AddressOfData)
		{
			if (pThunk->u1.Ordinal & DWORD(1) << 31)
			{
				std::cout << "	" << std::hex << " Ordinal   " << (pThunk->u1.Ordinal ^ 0x8000000000000000) << std::endl;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(DWORD64(m_pvImageBase) + RVA2Offset(pThunk->u1.AddressOfData));
				std::cout << "	" << std::hex << pIBN->Hint << " " << GetNameByRVA((DWORD64)pThunk->u1.AddressOfData + sizeof(WORD))<< std::endl;
			}
			++pThunk;
		}
		++m_pIID;
	}
}

void CPEInfo::PrintImportTable64()
{
	ULONG uSize;
	m_pIID = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(m_pvImageBase, FALSE, IMAGE_DIRECTORY_ENTRY_IMPORT, &uSize);
	if (m_pIID == NULL)
		return;

	while (m_pIID->FirstThunk)
	{
		std::cout << GetNameByRVA(m_pIID->Name) << std::endl;
		std::cout << "	" << std::hex << m_pIID->FirstThunk << " " << "Import Address Table" << std::endl;
		std::cout << "	" << std::hex << m_pIID->OriginalFirstThunk << " " << "Import Name Table" << std::endl;
		std::cout << "	" << std::hex << m_pIID->TimeDateStamp << " " << "time date stamp" << std::endl;
		std::cout << "	" << std::hex << m_pIID->ForwarderChain << " " << "Index of first forwarder reference" << std::endl;

		PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(DWORD64(m_pvImageBase) + RVA2Offset(m_pIID->FirstThunk));
		while (pThunk->u1.AddressOfData)
		{
			if (pThunk->u1.Ordinal & (ULONGLONG(1) << 63))
			{
				std::cout << "	" << std::hex << " Ordinal   " << (pThunk->u1.Ordinal ^ (ULONGLONG(1) << 63)) << std::endl;
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)(DWORD64(m_pvImageBase) + RVA2Offset(pThunk->u1.AddressOfData));
				std::cout << "	" << std::hex << pIBN->Hint << " " << GetNameByRVA((DWORD64)pThunk->u1.AddressOfData + sizeof(WORD))<< std::endl;
			}
			++pThunk;
		}
		++m_pIID;
	}
}