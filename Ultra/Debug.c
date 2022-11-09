#include <Windows.h>
#include <stdio.h>
#include "Common.h"


BOOL ReportError(CONST CHAR* FuncName, CONST CHAR* ApiName) {
	printf("\t[!] \" !%s:%s \" [FAILED] With Error: %d | 0x%0.8X \n", FuncName, ApiName, GetLastError(), GetLastError());
	return FALSE;
}


BOOL ReportErrorEx(CONST CHAR* FuncName, CONST CHAR* ApiName, DWORD dwError) {
	printf("\t[!] \" !%s:%s \" [FAILED] With Error: %d | [ %d | 0x%0.8X ] \n", FuncName, ApiName, GetLastError(), dwError, dwError);
	return FALSE;
}
