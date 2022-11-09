#include <Windows.h>
#include <stdio.h>
#include <RestartManager.h>

#include "Common.h"

#pragma comment (lib, "Rstrtmgr.lib")




BOOL KillParentProcess(IN LPCWSTR FileName) {

	BOOL				bSTATE				= TRUE;
	PRM_PROCESS_INFO	ProcessInfo			= NULL;
	HANDLE				hProcess			= NULL;

	DWORD				dwReturn			= NULL,
						dwReason			= NULL,
						dwSessionHandle		= NULL,
						dwError				= NULL;

	UINT				nProcInfoNeeded		= 0,
						nProcInfo			= 0;
	
	WCHAR				szSessionKey[CCH_RM_SESSION_KEY + 1];


	RtlSecureZeroMemory(szSessionKey, sizeof(szSessionKey));


	if ((dwError = RmStartSession(&dwSessionHandle, 0x0, szSessionKey)) != ERROR_SUCCESS) {
		bSTATE = ReportErrorEx("KillParentProcess", "RmStartSession", dwError); goto _EndOfFunc;
	}

	if ((dwError = RmRegisterResources(dwSessionHandle, 1, &FileName, 0, NULL, 0, NULL)) != ERROR_SUCCESS) {
		bSTATE =  ReportErrorEx("KillParentProcess", "RmRegisterResources", dwError); goto _EndOfFunc;
	}


	dwReturn = RmGetList(dwSessionHandle, &nProcInfoNeeded, &nProcInfo, NULL, &dwReason);
	if (dwReturn != ERROR_MORE_DATA || nProcInfoNeeded == 0) {
		bSTATE = ReportErrorEx("KillParentProcess", "RmGetList[1]", dwReturn); goto _EndOfFunc;
	}


	ProcessInfo = (PRM_PROCESS_INFO)malloc(sizeof(RM_PROCESS_INFO) * nProcInfoNeeded);
	if (ProcessInfo == NULL) {
		bSTATE = ReportError("KillParentProcess", "malloc"); goto _EndOfFunc;
	}

	RtlSecureZeroMemory(ProcessInfo, sizeof(RM_PROCESS_INFO) * nProcInfoNeeded);

	nProcInfo = nProcInfoNeeded;
	dwReturn = RmGetList(dwSessionHandle, &nProcInfoNeeded, &nProcInfo, ProcessInfo, &dwReason);
	if (dwReturn != ERROR_SUCCESS || nProcInfoNeeded == 0) {
		bSTATE =  ReportErrorEx("KillParentProcess", "RmGetList[2]", dwReturn); goto _EndOfFunc;
	}


	for (INT i = 0; i < nProcInfo; i++) {

		if (ProcessInfo[i].Process.dwProcessId != NULL && ProcessInfo[i].Process.dwProcessId != GetCurrentProcessId()) {
			hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessInfo[i].Process.dwProcessId);
			if (hProcess)
				bSTATE = TerminateProcess(hProcess, 1);
/*
			// we can do this, but this can takes more time
			dwReturn = RmShutdown(dwSessionHandle, RmForceShutdown, NULL);
			if (dwReturn != ERROR_SUCCESS) {
				bSTATE = ReportErrorEx("KillParentProcess", "RmShutdown", dwReturn);
			}
*/
		}
	}


_EndOfFunc:
	if (ProcessInfo)
		free(ProcessInfo);
	if (dwSessionHandle)
		RmEndSession(dwSessionHandle);
	if (hProcess)
		CloseHandle(hProcess);
	if (bSTATE)
		Sleep(500);
	return bSTATE;
}