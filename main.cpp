#include <Windows.h>
#include <Shlwapi.h>
#include <iostream>
#include "PEInfo.h"
#pragma comment(lib, "shlwapi.lib")
using namespace std;

int wmain(int argc, wchar_t **args)
{
	if (argc != 3)
		return 0;

	wstring sParam = args[1];
	wstring sPath = args[2];

	if (!PathFileExists(sPath.c_str()))
	{
		std::cout << "can not find the file" << std::endl;
		return -1;
	}

	CPEInfo *pInfo = new CPEInfo(sPath.c_str());

	if (!pInfo->IsPEFile())
	{
		std::cout << "it is not pe file" << std::endl;
		return -1;
	}

	if (sParam == L"-imports")
	{
		pInfo->PrintImportTable();
		pInfo->PrintSections();
	}
	else if (sParam == L"-exports")
	{
		pInfo->PrintExportTable();
		pInfo->PrintSections();
	}

	delete pInfo;
	return 0;
}