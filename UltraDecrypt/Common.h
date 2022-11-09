#pragma once

#include <Windows.h>




#ifndef COMMON_H
#define COMMON_H

// print error messages & info [from Debug.c]
BOOL ReportError(CONST CHAR* FuncName, CONST CHAR* ApiName);
BOOL ReportErrorEx(CONST CHAR* FuncName, CONST CHAR* ApiName, DWORD dwError);


// do the actual decryption part [from Decrypt.c]
BOOL InstallDecryption(IN LPWSTR szFileName);

// loop through all the files in a given directory
BOOL FetchFilesFromDirs(IN LPWSTR Dir);

#endif // !COMMON_H