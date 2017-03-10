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
	BOOL		LoadFile(LPCWSTR sPath);				// 读取文件
	DWORD64		RVA2Offset(DWORD64 dwRVA);				// RVA转换为文件偏移地址
	std::string	GetNameByRVA(DWORD64 dwRVA);			// 根据RVA获取字符串内容
	DWORD64		GetHeaderSize();						// DOS头+NT头+区表
	void		PrintImportTable32();
	void		PrintImportTable64();
	
private:
	PIMAGE_DOS_HEADER			m_pDosHeader;			// DOS头
	PIMAGE_NT_HEADERS32			m_pNtHeader32;
	PIMAGE_NT_HEADERS64			m_pNtHeader64;			// NT头
	BOOL						m_bPE32;				// 是否为32位pe
	LPVOID						m_pvImageBase;			// 基地址
	PIMAGE_SECTION_HEADER		m_pFirstSectHeader;		// 块表
	PIMAGE_IMPORT_DESCRIPTOR	m_pIID;					// 导入目录
	PIMAGE_EXPORT_DIRECTORY		m_pIED;					// 导出目录
};