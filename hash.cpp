#include "heder/hash.h"

#include <windows.h>
#include <wincrypt.h>

#include <cstdio>

using namespace std;

string calculateSHA256(const string& filePath)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return "HASH_ERROR";
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA_256,
            0,
            0,
            &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "HASH_ERROR";
    }

    HANDLE hFile = CreateFileA(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return "FILE_ACCESS_ERROR";
    }

    BYTE buffer[8192];
    DWORD bytesRead;

    while (ReadFile(
        hFile,
        buffer,
        sizeof(buffer),
        &bytesRead,
        NULL))
    {
        if (bytesRead == 0)
            break;

        if (!CryptHashData(
                hHash,
                buffer,
                bytesRead,
                0))
        {
            CloseHandle(hFile);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            return "HASH_ERROR";
        }
    }

    BYTE hash[32];
    DWORD hashSize = sizeof(hash);

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            hash,
            &hashSize,
            0))
    {
        CloseHandle(hFile);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return "HASH_ERROR";
    }

    CloseHandle(hFile);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    char hex[65];

    for (DWORD i = 0; i < hashSize; i++)
    {
        sprintf_s(
            &hex[i * 2],
            3,
            "%02x",
            hash[i]
        );
    }

    hex[64] = '\0';

    return string(hex);
}