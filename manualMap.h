#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define GET_NT_HEADER(pBase) reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pBase)->e_lfanew)
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

bool MapIt(BYTE* DllFile, UINT size, PVOID* baseaddr);