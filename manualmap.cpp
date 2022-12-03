#include "manualMap.h"

bool isValidDll(BYTE* DllFile, UINT size) {

	if (size < 0x1000) {
		puts("DLL too small to be valid");
		return false;
	}

	
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(DllFile)->e_magic != 0x5A4D) {
		puts("DLL not a PE file");
		return false;
	}


	
#ifdef _WIN64
#define VALID_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define VALID_MACHINE IMAGE_FILE_MACHINE_I386
#endif
	PIMAGE_NT_HEADERS ntHeader = GET_NT_HEADER(DllFile);
	if (ntHeader->FileHeader.Machine != VALID_MACHINE) {
		puts("Invalid platform");
		return false;
	}

	return true;
}

void mapSections(BYTE* pTargetBase, BYTE* dllBase, UINT numSections) {
	auto* dllSectionHeader = IMAGE_FIRST_SECTION(GET_NT_HEADER(dllBase));
	for (UINT i = 0; i != numSections; i++, dllSectionHeader++) {
		//printf("mapping %s section to RVA 0x%X\n", dllSectionHeader->Name, dllSectionHeader->VirtualAddress);
		memcpy(pTargetBase + dllSectionHeader->VirtualAddress, dllBase + dllSectionHeader->PointerToRawData, dllSectionHeader->SizeOfRawData);
	}
}

static inline void* offsetPtr(void* ptr, ptrdiff_t offset) {
	return (void*)(reinterpret_cast<BYTE*>(ptr) + offset);
}

void relocateDll(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
#define RELOC_PLATFORM_ISVALID32(type) (type == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_PLATFORM_ISVALID64(type) (type == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_PLATFORM_ISVALID(type) RELOC_PLATFORM_ISVALID64(type)
#else
#define RELOC_PLATFORM_ISVALID(type) RELOC_PLATFORM_ISVALID32(type)
#endif

	ptrdiff_t relocDelta = reinterpret_cast<ptrdiff_t>(pTargetBase - pOptHeader->ImageBase);

	if (!relocDelta) {
		return;
	}

	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		return;
	}

	auto pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pRelocData->VirtualAddress) {
		
		UINT numEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD));
		WORD* TypeOffset = reinterpret_cast<WORD*>(pRelocData + 1);
		for (; numEntries--; TypeOffset++) {
			UINT type = *TypeOffset >> 12;
			UINT offset = *TypeOffset & 0xfff;
			if (RELOC_PLATFORM_ISVALID(type)) {
				UINT_PTR* patchAddr = reinterpret_cast<UINT_PTR*>(pTargetBase + pRelocData->VirtualAddress + offset);
				*patchAddr += relocDelta;
			}
		}

		
		pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(offsetPtr(pRelocData, pRelocData->SizeOfBlock));
	}
	return;
}

bool fixIAT(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) { return true; }

	auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (pImportDesc->Name) {
		char* szMod = reinterpret_cast<char*>(pTargetBase + pImportDesc->Name);
		//printf("Loading %s\n", szMod);

		HINSTANCE hDll = LoadLibraryA(szMod);
		if (!hDll) {
			puts("load IAT library failed");
			return false;
		}
		UINT_PTR* pThunkRef = reinterpret_cast<UINT_PTR*>(pTargetBase + pImportDesc->OriginalFirstThunk);
		FARPROC* pFuncRef = reinterpret_cast<FARPROC*>(pTargetBase + pImportDesc->FirstThunk);
		if (!pThunkRef) { pThunkRef = reinterpret_cast<UINT_PTR*>(pFuncRef); }
		for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
			if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
				*pFuncRef = GetProcAddress(hDll, reinterpret_cast<const char*>(IMAGE_ORDINAL(*pThunkRef)));
			}
			else {
				auto* thunkData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pTargetBase + (*pThunkRef));
				*pFuncRef = GetProcAddress(hDll, thunkData->Name);
			}
		}
		++pImportDesc;
	}
	return true;
}

void TlsRun(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) { return; }
	auto pTls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	auto pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
	if (pCallBack) {
		for (; *pCallBack; pCallBack++) {
			(*pCallBack)(reinterpret_cast<void*>(pTargetBase), DLL_PROCESS_ATTACH, nullptr);
		}
	}
}

bool MapIt(BYTE* DllFile, UINT fSize, PVOID* baseaddr) {
	
	if (!isValidDll(DllFile, fSize)) {
		puts("DLL not valid");
		return false;
	}

	
	PIMAGE_NT_HEADERS		pNtHeader = GET_NT_HEADER(DllFile);
	PIMAGE_OPTIONAL_HEADER  pOptHeader = &pNtHeader->OptionalHeader;
	PIMAGE_FILE_HEADER		pFileHeader = &pNtHeader->FileHeader;

	
	BYTE* pTargetBase = (BYTE*)baseaddr;
	

	//printf("\nCopying headers into target process.\n");
	memmove(pTargetBase, DllFile, pNtHeader->OptionalHeader.SizeOfHeaders);

	mapSections(pTargetBase, DllFile, pFileHeader->NumberOfSections);

	if (pTargetBase != (BYTE*)pOptHeader->ImageBase) {
		relocateDll(pTargetBase, pOptHeader);
	}
	if (!fixIAT(pTargetBase, pOptHeader)) {
		puts("failed to fix IAT");
		VirtualFree(pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	TlsRun(pTargetBase, pOptHeader);

	//auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pTargetBase + pOptHeader->AddressOfEntryPoint);
	//_DllMain(reinterpret_cast<void*>(pTargetBase), DLL_PROCESS_ATTACH, nullptr);


	//VirtualFree(pTargetBase, 0, MEM_RELEASE);
	return true;
}