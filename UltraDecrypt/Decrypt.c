#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

#include "Common.h"


#define DATA1_SIZE	8
#define DATA2_SIZE	7

#define KEY_SIZE                    0x14                                            //          20
#define D1_D2_SIZE                  (sizeof(g_DATA1) + sizeof(g_DATA2))             //          15
#define KEY_PART_SIZE               0x04                                            //          4
#define ENC_TYPE_SIZE               0x04                                            //          4

#define MAX_FULL_ENCRYPTION         0xFFFFFFF                                       //          268435455       [268 MB]
#define PARTIAL_ENCRYPTION          0xFFFF                                          //          65535


#define TOTAL_CONFIG_SIZE           (D1_D2_SIZE + KEY_PART_SIZE + ENC_TYPE_SIZE)    //          23



// encryption types
BYTE        g_PartiallyEnc	[ENC_TYPE_SIZE] = { 0xA1, 0xA1, 0xA1, 0xA1 };
BYTE        g_FullyEnc		[ENC_TYPE_SIZE] = { 0xB2, 0xB2, 0xB2, 0xB2 };

// hmac key generation seeds
BYTE        g_DATA1			[DATA1_SIZE];
BYTE        g_DATA2			[DATA2_SIZE];


typedef struct _FileInfo
{
    HANDLE      hFile;                          // file handle
    DWORD       dwFileSize;                     // file total size
    DWORD       dwActualWorkSize;               // size that we will read
    DWORD       dwActualWriteSize;              // size that we will use to write (the original size of the file before encryption)
    PBYTE       pHmacKey;                       // the hmac key - used for the encryption algo
    PBYTE       pFileByte;                      // pointer to data read    
    BOOL        PartiallyEnc;                   // is partially encrypted file ?

} FileInfo, * PFileInfo;

typedef struct _USTRING
{
    DWORD	    Length;
    DWORD	    MaximumLength;
    PVOID	    Buffer;

} USTRING, * PUSTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );


fnSystemFunction032 g_SystemFunction032 = NULL;




BOOL GenHmacKey(PBYTE HmacKey) {

    HCRYPTPROV  hProv = NULL;
    HCRYPTHASH  hHash = NULL;
    HCRYPTKEY   hKey = NULL;
    HCRYPTHASH  hHmacHash = NULL;
    PBYTE       pbHash = NULL;
    DWORD       dwDataLen = NULL;
    BOOL        bSTATE = TRUE;
    HMAC_INFO   HmacInfo = { 0 };

    RtlSecureZeroMemory(&HmacInfo, sizeof(HmacInfo));
    HmacInfo.HashAlgid = CALG_SHA1;


    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptHashData(hHash, g_DATA1, sizeof(g_DATA1), 0)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmacHash)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptHashData(hHmacHash, g_DATA2, sizeof(g_DATA2), 0)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if ((pbHash = (BYTE*)malloc(dwDataLen)) == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (HmacKey != NULL) {
        memcpy(HmacKey, pbHash, dwDataLen);
    }


_EndOfFunc:
    if (hHmacHash)
        CryptDestroyHash(hHmacHash);
    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    if (pbHash)
        ZeroMemory(pbHash, dwDataLen); free(pbHash);

    return bSTATE;
}




BOOL GetFileHandle(IN LPWSTR szFileName, OUT HANDLE* hFileHandle, OUT DWORD* dwFileSize) {

    HANDLE          hFile = INVALID_HANDLE_VALUE;
    DWORD           dwError = NULL;
    LARGE_INTEGER   FileSize = { 0 };

    if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE | DELETE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        return ReportError("GetFileHandle", "CreateFileW[1]");
    }

    if (!GetFileSizeEx(hFile, &FileSize) || FileSize.QuadPart == NULL) {
        return ReportError("GetFileHandle", "GetFileSizeEx");
    }

    *hFileHandle = hFile;
    *dwFileSize = FileSize.QuadPart;

    if (*hFileHandle == INVALID_HANDLE_VALUE || *dwFileSize == NULL)
        return FALSE;

    return TRUE;
}



BOOL ReadFileBuffer(IN HANDLE hFile, IN DWORD dwFileSize, OUT BYTE* pBuffer) {

    if (hFile == NULL || hFile == INVALID_HANDLE_VALUE || dwFileSize == NULL)
        return FALSE;


    BOOL    bSTATE = TRUE;
    DWORD   dwNumberOfBytesRead = NULL;
    ULONG   Offset = -1 * dwFileSize;

    if (SetFilePointer(hFile, Offset, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
        bSTATE = ReportError("ReadFileBuffer", "SetFilePointer");


    if ((pBuffer && !ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL)) || dwNumberOfBytesRead != dwFileSize)
        bSTATE = ReportError("ReadFileBuffer", "ReadFile");

    return bSTATE;
}



BOOL WriteFileBuffer(IN FileInfo St) {

    BOOL  bSTATE = TRUE;
    DWORD dwNmbrOfBytesWritten = NULL;


    ULONG Offset = -1 * St.dwActualWorkSize;

    if (SetFilePointer(St.hFile, Offset, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
        bSTATE = ReportError("WriteFileBuffer", "SetFilePointer");

    if ((bSTATE && !WriteFile(St.hFile, St.pFileByte, St.dwActualWriteSize, &dwNmbrOfBytesWritten, NULL)) || dwNmbrOfBytesWritten != St.dwActualWriteSize)
        bSTATE = ReportError("WriteFileBuffer", "WriteFile");

    // since we added 23 bytes to the end of the file when encrypting, we simply cut them out now
    if (!SetEndOfFile(St.hFile))
        bSTATE = ReportError("WriteFileBuffer", "SetEndOfFile");

    return bSTATE;
}



BOOL InitializeStruct(IN LPWSTR szFileName, OUT FileInfo* St) {

    HANDLE      hFile                       = INVALID_HANDLE_VALUE;
    DWORD       dwFile                      = NULL;
    PBYTE       pPossibleTypePosition       = NULL,
                pPossiblePartKeyPosition    = NULL;
    BYTE        pFirstRead                  [TOTAL_CONFIG_SIZE];

    // getting the handle
    if (!GetFileHandle(szFileName, &hFile, &dwFile))
        return FALSE;
    // filling some data
    St->hFile = hFile;
    St->dwFileSize = dwFile;

    // reading the last 23 bytes, that can tell us about the file encryption config
    if (!ReadFileBuffer(hFile, TOTAL_CONFIG_SIZE, pFirstRead))
        return FALSE;
    
    // calculating the offset ot possible *encryption type* data
    pPossibleTypePosition = (PBYTE)(pFirstRead);
    // get the key part (first 4 bytes of it from the file to compare to what we generated)
    pPossiblePartKeyPosition = (PBYTE)(pFirstRead + KEY_PART_SIZE);


    // if partially encrypted (0xA1A1A1A1)
    if (*(ULONG*)pPossibleTypePosition == *(ULONG*)g_PartiallyEnc) {
        St->PartiallyEnc = TRUE;
        St->dwActualWorkSize = PARTIAL_ENCRYPTION + TOTAL_CONFIG_SIZE;

    }
    // else if fully encrypted file (0xB2B2B2B2)
    else if (*(ULONG*)pPossibleTypePosition == *(ULONG*)g_FullyEnc) {
        St->PartiallyEnc = FALSE;
        St->dwActualWorkSize = dwFile;

    }
    // encryption type isnt found (file not encrypted - or corupted)
    else {
        printf("[-] File is not Encrypted \n");
        return FALSE; // not encrypted or currupted
    }


    
    // now we need to get the hmac seeds to calculate the decryption key
    RtlSecureZeroMemory(g_DATA1, DATA1_SIZE);
    RtlSecureZeroMemory(g_DATA2, DATA2_SIZE);
    
    memcpy(g_DATA1, (PVOID)(pFirstRead + ENC_TYPE_SIZE + KEY_PART_SIZE + DATA2_SIZE), DATA1_SIZE);
    memcpy(g_DATA2, (PVOID)(pFirstRead + ENC_TYPE_SIZE + KEY_PART_SIZE), DATA2_SIZE);

    if (g_DATA1 == NULL || g_DATA2 == NULL)
        return FALSE;

    // generating the key
    St->pHmacKey = (PBYTE)LocalAlloc(LPTR, KEY_SIZE);
    if (!St->pHmacKey || (St->pHmacKey && !GenHmacKey(St->pHmacKey))) {
        return FALSE;
    }
    
    // if not equal we exit
    if (*(ULONG*)St->pHmacKey != *(ULONG*)pPossiblePartKeyPosition)
        return FALSE;

    St->pFileByte = (PBYTE)LocalAlloc(LPTR, St->dwActualWorkSize);

    if (!ReadFileBuffer(hFile, St->dwActualWorkSize, St->pFileByte))
        return FALSE;


    // set dwActualWriteSize [which is the dwActualWorkSize - TOTAL_CONFIG_SIZE] to get the original size of the file before encryption
    St->dwActualWriteSize = St->dwActualWorkSize - TOTAL_CONFIG_SIZE;

    return TRUE;
}




BOOL InstallDecryption(IN LPWSTR szFileName) {

    BOOL        bSTATE  = TRUE;
    NTSTATUS	STATUS  = NULL;
    FileInfo    St      = { 0 };
    USTRING     Key     = { 0 };
    USTRING     Buf     = { 0 };

    RtlSecureZeroMemory(&St, sizeof(FileInfo));
    RtlSecureZeroMemory(&Key, sizeof(USTRING));
    RtlSecureZeroMemory(&Buf, sizeof(USTRING));


    if (!InitializeStruct(szFileName, &St)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }


    Key.Buffer = (PVOID)St.pHmacKey;
    Key.Length = Key.MaximumLength = KEY_SIZE;

    Buf.Buffer = (PVOID)St.pFileByte;
    Buf.Length = Buf.MaximumLength = St.dwActualWriteSize; 

    

    if (!g_SystemFunction032)
        g_SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if ((STATUS = g_SystemFunction032(&Buf, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }



    if (!WriteFileBuffer(St)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }


_EndOfFunc:
    if (St.pHmacKey)
        LocalFree(St.pHmacKey);
    if (St.pFileByte)
        LocalFree(St.pFileByte);
    if (St.hFile)
        CloseHandle(St.hFile);
    return bSTATE;
}






