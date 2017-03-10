#include <Windows.h>
#include <string>

class CPEInfo
{
public:
	CPEInfo(LPCWSTR sPath);
	~CPEInfo();

public:
	BOOL IsPEFile();
	void PrintImportTable();
	void PrintExportTable();
	void PrintSections();
	
private:
	BOOL		LoadFile(LPCWSTR sPath);				// ��ȡ�ļ�
	DWORD64		RVA2Offset(DWORD64 dwRVA);				// RVAת��Ϊ�ļ�ƫ�Ƶ�ַ
	std::string	GetNameByRVA(DWORD64 dwRVA);			// ����RVA��ȡ�ַ�������
	DWORD64		GetHeaderSize();						// DOSͷ+NTͷ+����
	void		PrintImportTable32();
	void		PrintImportTable64();
	
private:
	PIMAGE_DOS_HEADER			m_pDosHeader;			// DOSͷ
	PIMAGE_NT_HEADERS32			m_pNtHeader32;
	PIMAGE_NT_HEADERS64			m_pNtHeader64;			// NTͷ
	BOOL						m_bPE32;				// �Ƿ�Ϊ32λpe
	LPVOID						m_pvImageBase;			// ����ַ
	PIMAGE_SECTION_HEADER		m_pFirstSectHeader;		// ���
	PIMAGE_IMPORT_DESCRIPTOR	m_pIID;					// ����Ŀ¼
	PIMAGE_EXPORT_DIRECTORY		m_pIED;					// ����Ŀ¼
};