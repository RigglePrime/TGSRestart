#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <atlstr.h>
#include <fstream>
#include <vector>
#include <sstream>
#include "constants.h"

#pragma comment(lib, "wbemuuid.lib")

// Set a default startup type if we fail later
DWORD g_dwTgServiceStartType = SERVICE_AUTO_START;

// We have to cache errors as soon as they occur since we usually clean up immediately after
DWORD g_dwLastError = 0;
DWORD GetAndCacheLastError() {
	g_dwLastError = GetLastError();
	return g_dwLastError;
}

/// <summary>
/// Tries to kill the specified process. On access denied, assumes the process already died.
/// </summary>
/// <param name="pid">PID of the process to be killed</param>
/// <returns>True if successful, false if not</returns>
BOOL KillProcess(DWORD pid) {
	printf("Killing PID %d\n", pid);
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProcess == NULL)
		return false;
	BOOL ret = TerminateProcess(hProcess, 0);
	CloseHandle(hProcess);
	if (!ret) {
		DWORD error = GetAndCacheLastError();
		// This means the process is either already dead, or we don't have access. We'll assume it died.
		if (error == ERROR_ACCESS_DENIED)
			return true;
	}
	return ret;
}

/// <summary>
/// Disables and stops the TGS service. Stores the start type in g_dwTgServiceStartType (global)
/// </summary>
/// <param name="schSCManager">Service manager handle, must have all access</param>
/// <returns>True if successful, false if not</returns>
BOOL DisableAndStopTGSService(SC_HANDLE schSCManager) {
	SC_HANDLE schService;
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwBytesNeeded, cbBufSize;
	LPQUERY_SERVICE_CONFIG lpsc;

	if (schSCManager == NULL)
		return false;
	schService = OpenServiceW(schSCManager, TGS_SERVICE, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
	if (schService == NULL)
		return false;
	// With this call we get the amount of space needed
	if (QueryServiceConfig(schService, NULL, 0, &dwBytesNeeded)) {
		// This should never happen
		puts("If you see this, something's gone very wrong.");
		MessageBoxExW(NULL, TEXT("What have you done"), TEXT("@_@"), MB_HELP | MB_ICONERROR, 0);
		exit(0xdead);
	}
	if (GetAndCacheLastError() != ERROR_INSUFFICIENT_BUFFER) {
		printf("Could not determine buffer size (%d)\n", GetAndCacheLastError());
		return false;
	}
	cbBufSize = dwBytesNeeded; // Get the amount of space we need
	lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
	if (lpsc == NULL) {
		puts("Alloc failed");
		MessageBoxExW(NULL, TEXT("Could not allocate memory"), TEXT("@_@"), MB_OK | MB_ICONERROR, 0);
		exit(1);
	}

	if (!QueryServiceConfig(schService, lpsc, cbBufSize, &dwBytesNeeded)) {
		printf("QueryServiceConfig failed (%d)\n", GetAndCacheLastError());
		CloseServiceHandle(schService);
		return false;
	}
	
	// Save the startup type so we don't change it later
	g_dwTgServiceStartType = lpsc->dwStartType;

	LocalFree(lpsc);
	if (!ChangeServiceConfig(
		schService,        // handle of service 
		SERVICE_NO_CHANGE, // service type: no change 
		SERVICE_DISABLED,  // disable service
		SERVICE_NO_CHANGE, // error control: no change 
		NULL,              // binary path: no change 
		NULL,              // load order group: no change 
		NULL,              // tag ID: no change 
		NULL,              // dependencies: no change 
		NULL,              // account name: no change 
		NULL,              // password: no change 
		NULL))             // display name: no change)
	{
		CloseServiceHandle(schService);
		printf("Could not disable the service (%d)\n", GetAndCacheLastError());
		return false;
	}

	if (!QueryServiceStatusEx(
		schService,
		SC_STATUS_PROCESS_INFO,
		(LPBYTE)&ssStatus,
		sizeof(SERVICE_STATUS_PROCESS),
		&dwBytesNeeded))
	{
		printf("Could not query service status (%d)\n", GetAndCacheLastError());
		CloseServiceHandle(schService);
		return false;
	}

	CloseServiceHandle(schService);

	if (ssStatus.dwCurrentState == SERVICE_STOPPED)
	{
		puts("Service already dead");
		return true;
	}

	// Kill process immediately (as opposed to stopping the service) and let the orphans live
	if (!KillProcess(ssStatus.dwProcessId))
	{
		printf("Could not kill service process (%d)\n", GetAndCacheLastError());
		return false;
	}
	return true;
}

/// <summary>
/// Enables and starts the TGS service
/// </summary>
/// <param name="schSCManager">Service manager handle, must have all access</param>
/// <returns>True if successful, false if not</returns>
BOOL EnableAndStartTGSService(SC_HANDLE schSCManager) {
	SC_HANDLE schService;
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwOldCheckPoint;
	DWORD dwStartTickCount;
	DWORD dwWaitTime;
	DWORD dwBytesNeeded;
	BOOL ret = false;

	if (schSCManager == NULL)
		return false;
	schService = OpenServiceW(schSCManager, TGS_SERVICE, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START);
	if (schService == NULL)
		return false;
	if (!ChangeServiceConfig(
		schService,
		SERVICE_NO_CHANGE,
		g_dwTgServiceStartType,
		SERVICE_NO_CHANGE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL))
	{
		printf("ChangeServiceConfig failed (%d)\n", GetAndCacheLastError());
	}

	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // information level
		(LPBYTE)&ssStatus,              // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))                // size needed if buffer is too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetAndCacheLastError());
		CloseServiceHandle(schService);
		return false;
	}

	// Check if the service is already running
	if (ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
	{
		puts("Service already running");
		CloseServiceHandle(schService);
		return true;
	}

	// Save the tick count and initial checkpoint.
	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	// Wait for the service to stop before attempting to start it.
	while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds. 
		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status until the service is no longer stop pending. 
		if (!QueryServiceStatusEx(
			schService,                     // handle to service 
			SC_STATUS_PROCESS_INFO,         // information level
			(LPBYTE)&ssStatus,              // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))                // size needed if buffer is too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetAndCacheLastError());
			CloseServiceHandle(schService);
			return false;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.
			dwStartTickCount = GetTickCount();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount() - dwStartTickCount > ssStatus.dwWaitHint)
			{
				printf("Timeout waiting for service to stop\n");
				CloseServiceHandle(schService);
				return false;
			}
		}
	}

	// Attempt to start the service.
	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))       // no arguments 
	{
		printf("StartService failed (%d)\n", GetAndCacheLastError());
		CloseServiceHandle(schService);
		return false;
	}
	else puts("Service start pending...");

	// Check the status until the service is no longer start pending. 
	if (!QueryServiceStatusEx(
		schService,                     // handle to service 
		SC_STATUS_PROCESS_INFO,         // info level
		(LPBYTE)&ssStatus,              // address of structure
		sizeof(SERVICE_STATUS_PROCESS), // size of structure
		&dwBytesNeeded))                // if buffer too small
	{
		printf("QueryServiceStatusEx failed (%d)\n", GetAndCacheLastError());
		CloseServiceHandle(schService);
		return false;
	}

	// Save the tick count and initial checkpoint.

	dwStartTickCount = GetTickCount();
	dwOldCheckPoint = ssStatus.dwCheckPoint;

	while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
	{
		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth the wait hint, but no less than 1 second and no 
		// more than 10 seconds. 
		dwWaitTime = ssStatus.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		// Check the status again. 
		if (!QueryServiceStatusEx(
			schService,             // handle to service 
			SC_STATUS_PROCESS_INFO, // info level
			(LPBYTE)&ssStatus,              // address of structure
			sizeof(SERVICE_STATUS_PROCESS), // size of structure
			&dwBytesNeeded))                // if buffer too small
		{
			printf("QueryServiceStatusEx failed (%d)\n", GetAndCacheLastError());
			break;
		}

		if (ssStatus.dwCheckPoint > dwOldCheckPoint)
		{
			// Continue to wait and check.
			dwStartTickCount = GetTickCount64();
			dwOldCheckPoint = ssStatus.dwCheckPoint;
		}
		else
		{
			if (GetTickCount64() - dwStartTickCount > 10000)
			{
				// More than 10 seconds have passed and the service hasn't started yet
				break;
			}
		}
	}

	// Determine whether the service is running.
	if (ssStatus.dwCurrentState == SERVICE_RUNNING)
	{
		printf("Service started successfully.\n");
		ret = true;
	}
	else
	{
		printf("Service not started. \n");
		printf("  Current State: %d\n", ssStatus.dwCurrentState);
		printf("  Exit Code: %d\n", ssStatus.dwWin32ExitCode);
		printf("  Check Point: %d\n", ssStatus.dwCheckPoint);
		printf("  Wait Hint: %d\n", ssStatus.dwWaitHint);
	}

cleanup:
	CloseServiceHandle(schService);
	return ret;
}

/// <summary>
/// Searches a JSOn and replaces the value of a specified key
/// </summary>
/// <param name="haystack">std::string JSON</param>
/// <param name="key">Desired key to look for</param>
/// <param name="value">What to replace the value with</param>
/// <returns>True if successful, false if not</returns>
BOOL JsonFindAndReplaceValueOf(std::string* haystack, const char* key, const char* value) {
	if (haystack == NULL)
		return false;
	size_t szLocStart = (*haystack).find(key);
	size_t szLocEnd = (*haystack).find(",", szLocStart);
	if (szLocStart == std::string::npos || szLocEnd == std::string::npos) {
		printf("Could not locate '%s' in JSON\n", key);
		return false;
	}
	size_t keyLen = strlen(key);
	if (szLocEnd < szLocStart + keyLen) {
		puts("szLocEnd is before or equal to szLocStart + keyLen");
		return false;
	}
	(*haystack).replace(szLocStart + keyLen, szLocEnd - szLocStart - keyLen, value);
	return true;
}

/// <summary>
/// Does everything we need to do for DD. This includes getting query params and modifying its Instance.json
/// </summary>
/// <param name="pid">PID of the DD process</param>
/// <param name="pSvc">IWbemServices so we can get its command line params</param>
/// <returns>True if successful, false if not</returns>
BOOL HandleDreamdaemon(DWORD pid, IWbemServices* pSvc) {
	printf("Handling DD with PID %d\n", pid);
	HRESULT hres;
	if (pid == 0 || pSvc == NULL)
		return false;

	wchar_t query[128];
	StringCbPrintf(query, 128, TEXT("SELECT * FROM Win32_Process WHERE ProcessId = %d"), pid);

	// Exec our WMI query
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(query),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator
	);
	if (FAILED(hres)) {
		printf("Cannot execute query (%d)\n", GetAndCacheLastError());
		return false;
	}

	// We should only have one entry, no two processes can have the same PID
	IWbemClassObject* pclsObj;
	ULONG uReturn = 0;
	pEnumerator->Next(5000, 1, &pclsObj, &uReturn);
	if (uReturn == 0) {
		printf("Enumerator error (%d)\n", uReturn);
		return false;
	}

	// Get command line args
	VARIANT vtProp;
	pclsObj->Get(TEXT("CommandLine"), 0, &vtProp, 0, 0);
	int len = SysStringLen(vtProp.bstrVal) + 1;
	wchar_t* wcCommandLine = new wchar_t[len];
	wcscpy_s(wcCommandLine, len, vtProp.bstrVal);
	VariantClear(&vtProp);
	pclsObj->Release();

	int argc;
	LPWSTR* argv;
	LPWSTR wcsPath;
	LPWSTR wcsPort = NULL;
	LPWSTR wcsCommsKey = NULL;
	wchar_t* found;
	// Let Windows parse the args for us
	argv = CommandLineToArgvW(wcCommandLine, &argc);
	wcsPath = argv[0];
	found = wcsstr(wcsPath, TEXT("BYOND/bin/dreamdaemon.exe"));
	if (found == NULL) {
		puts("Could not remove BYOND part from path");
		LocalFree(argv);
		return false;
	}
	*found = 0; // Terminate string

	for (int i = 1; i < argc; i++) {
		// Look for the -port switch, a number should follow
		if (!wcscmp(argv[i], TEXT("-port"))) {
			i++;
			if (i >= argc) {
				// Shenanigans!!
				LocalFree(argv);
				puts("End of argv reached");
				return false;
			}
			wcsPort = argv[i];
			continue;
		}
		// Try to find the comms key
		const wchar_t* needle = TEXT("server_service=");
		found = wcsstr(argv[i], needle);
		if (found == NULL) {
			continue;
		}
		// Found!
		// If we can't see an & we're probably at the end of our string, so no termination needed
		wchar_t* end = wcsstr(found, TEXT("&"));
		if (end != NULL)
			*end = 0; // Terminate string
		// Offset by the needle so we only get the actual key
		wcsCommsKey = found + lstrlen(needle);
	}
	wprintf(L"Base path: %s, port: %s, comms key: %s\n", wcsPath, wcsPort, wcsCommsKey);
	if (wcsPath == NULL || wcsPort == NULL || wcsCommsKey == NULL) {
		puts("Error while trying to read parameters");
		LocalFree(argv);
		return false;
	}

	std::wstring path(wcsPath);
	path.append(INSTANCE_FILE);

	// + 1 for null termination, + 1 for a space
	int portLen = lstrlenW(wcsPort) + 1 + 1;
	char* aPort = new char[portLen];
	strcpy_s(aPort, portLen, " ");
	strcat_s(aPort, portLen, CW2A(wcsPort));
	// + 1 for null termination, + 2 for "", + 1 for a space
	int commsKeyLen = lstrlenW(wcsCommsKey) + 1 + 2 + 1;
	char* aCommsKey = new char[commsKeyLen];
	strcpy_s(aCommsKey, commsKeyLen, " \"");
	strcat_s(aCommsKey, commsKeyLen, CW2A(wcsCommsKey));
	strcat_s(aCommsKey, commsKeyLen, "\"");

	// Prevent accidental UAF
	wcsPath = NULL;
	wcsPort = NULL;
	wcsCommsKey = NULL;
	// Free the result from CommandLineToArgvW, as per documentation
	LocalFree(argv);

	_tprintf(TEXT("Writing to file '%s'... "), path.c_str());
	// Try opening the file
	std::fstream instanceFileFstream(path.c_str(), std::ios::in | std::ios::out);

	if (!instanceFileFstream.is_open()) {
		puts("File wasn't open");
		return false;
	}
	// Read the whole file into memory. It should be very small. If it's not it's a skill issue, enjoy having no RAM
	std::stringstream text;
	text << instanceFileFstream.rdbuf();
	std::string strFileText = text.str();
	instanceFileFstream.close();

	std::string procId(" ");
	procId += std::to_string(pid);
	// Json replace
	if (!JsonFindAndReplaceValueOf(&strFileText, "\"ReattachProcessID\":", procId.c_str()))
		return false;
	if (!JsonFindAndReplaceValueOf(&strFileText, "\"ReattachPort\":", aPort))
		return false;
	if (!JsonFindAndReplaceValueOf(&strFileText, "\"ReattachCommsKey\":", aCommsKey))
		return false;
	if (!JsonFindAndReplaceValueOf(&strFileText, "\"ReattachRequired\":", " true"))
		return false;

	// Truncate the file and dump the contents
	std::ofstream instanceFileOfStream(path.c_str(), std::ios::trunc);
	instanceFileOfStream << strFileText;
	instanceFileOfStream.flush();
	instanceFileOfStream.close();
	puts("done");
	return true;
}

/// <summary>
/// Initializes Wmi
/// </summary>
/// <param name="pLoc">Out pLoc</param>
/// <param name="pSvc">Out pSvc</param>
/// <returns>True if successful, false if not</returns>
HRESULT WmiInit(IWbemLocator** pLoc, IWbemServices** pSvc) {
	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		printf("CoInitializeEx failed (%d)\n", GetAndCacheLastError());
		return ERR_COINIT_FAILED;
	}

	hres = CoInitializeSecurity(
		NULL,
		-1,      // COM negotiates service                  
		NULL,    // Authentication services
		NULL,    // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
		RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
		NULL,             // Authentication info 
		EOAC_NONE,        // Additional capabilities
		NULL              // Reserved
	);
	if (FAILED(hres)) {
		printf("CoInitializeSecurity failed (%d)\n", GetAndCacheLastError());
		return ERR_COINIT_SEC_FAILED;
	}

	// Obtain the initial locator to Windows Management
	// on a particular host computer.
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)pLoc);
	if (FAILED(hres)) {
		printf("CoCreateInstance failed (%d)\n", GetAndCacheLastError());
		return ERR_COINIT_INSTANCE;
	}

	// Connect to the root\cimv2 namespace with the
	// current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = (*pLoc)->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // WMI namespace
		NULL,                    // User name
		NULL,                    // User password
		0,                       // Locale
		NULL,                    // Security flags                 
		0,                       // Authority       
		0,                       // Context object
		pSvc                     // IWbemServices proxy
	);

	if (FAILED(hres)) {
		printf("ConnectServer failed (%d)\n", GetAndCacheLastError());
		return ERR_WMI_CONNECT;
	}

	// Set the IWbemServices proxy so that impersonation
	// of the user (client) occurs.
	hres = CoSetProxyBlanket(
		*pSvc,                        // the proxy to set
		RPC_C_AUTHN_WINNT,            // authentication service
		RPC_C_AUTHZ_NONE,             // authorization service
		NULL,                         // Server principal name
		RPC_C_AUTHN_LEVEL_CALL,       // authentication level
		RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
		NULL,                         // client identity 
		EOAC_NONE                     // proxy capabilities     
	);

	if (FAILED(hres)) {
		printf("CoSetProxyBlanket failed (%d)\n", GetAndCacheLastError());
		return ERR_WMI_PROXYBLANKET;
	}

	return 0;
}

/// <summary>
/// Uninitializes Wmi, should be called for cleanup
/// </summary>
/// <param name="pLoc">pLoc to be released, is set to null</param>
/// <param name="pLoc">pSvc to be released, is set to null</param>
void WmiUninit(IWbemLocator** pLoc, IWbemServices** pSvc) {
	if (pLoc != NULL && *pSvc != NULL) {
		(*pLoc)->Release();
		*pLoc = NULL;
	}
	if (pSvc != NULL && *pSvc != NULL) {
		(*pSvc)->Release();
		*pSvc = NULL;
	}
	CoUninitialize();
}

int run(void) {
	HANDLE hProcessSnap = 0;
	PROCESSENTRY32 pe32;
	DWORD dwTgsPid = 0;
	DWORD ret = 0;
	IWbemLocator* pLoc = NULL;
	IWbemServices* pSvc = NULL;

	// Init Wmi (so we can get command line params)
	// Yes there are other ways, no they're not supported. I'm not calling
	// some undocumented ntdll.dll function that is bound to be changed
	HRESULT hres = WmiInit(&pLoc, &pSvc);
	if (FAILED(hres)) {
		WmiUninit(&pLoc, &pSvc);
		return hres;
	}

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);

	if (schSCManager == NULL) {
		printf("Service manager null (%d)\n", GetAndCacheLastError());
		ret = ERR_SVCMGR;
		goto cleanup;
	}

	// First we disable the service
	if (!DisableAndStopTGSService(schSCManager)) {
		printf("Disable failed (%d)\n", GetAndCacheLastError());
		ret = ERR_CANNOT_DISABLE;
		goto cleanup;
	}

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("Cannot create a snapshot (%d)\n", GetAndCacheLastError());
		ret = ERR_CANNOT_SNAP;
		goto cleanup;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)) {
		printf("Cannot get first process (%d)\n", GetAndCacheLastError());
		ret = ERR_PROC_ENTRY_FIRST;
		goto cleanup;
	}

	do {
		// Look for all Dreamdaemon processes
		if (!wcscmp(pe32.szExeFile, DD_EXE)) {
			HandleDreamdaemon(pe32.th32ProcessID, pSvc);
		}
		//else if (!wcscmp(pe32.szExeFile, TGS_EXE)) {
		//	KillProcess(pe32.th32ProcessID); // Just in case
		//}
	} while (Process32Next(hProcessSnap, &pe32));

cleanup:
	// If we fail at any point, try to re-enable the service
	if (!EnableAndStartTGSService(schSCManager)) {
		ret = ERR_CANNOT_ENABLE;
		MessageBoxExW(NULL,
			TEXT("Could not properly start the service. Please contact an administrator."),
			TEXT("@_@"),
			MB_OK | MB_ICONERROR,
			0);
	}
	// Release handles
	if (hProcessSnap != 0)
		CloseHandle(hProcessSnap);
	if (schSCManager != 0)
		CloseServiceHandle(schSCManager);
	WmiUninit(&pLoc, &pSvc);
	return ret;
}

int main(void) {
	// Ask the user if they meant to do this, just to be sure
	if (MessageBoxExW(NULL, TEXT("Would you like to restart TGS? This will not kill the game servers."), TEXT("Restart?"), MB_YESNO | MB_ICONINFORMATION, 0) != IDYES) {
		return 0;
	}
	wchar_t err[384] = TEXT("Could not format the error code");
	TCHAR sysMsg[256];
	int ret = 0;
	while (1) {
		// Run and get the return value
		ret = run();
		if (ret == 0) {
			MessageBoxExW(NULL, TEXT("The server has been restarted. Please ensure everything is working correctly."), TEXT("Success"), MB_OK | MB_ICONINFORMATION, 0);
			break;
		}
		// Uh oh, error!
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, g_dwLastError,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			sysMsg, 256, NULL);
		StringCbPrintf(err, 384,
			TEXT("The program encountered an error, error code 0x%08X, 0x%08X\n%s"),
			ret, g_dwLastError, sysMsg);
		// Ask the user if they want to retry
		if (MessageBoxExW(NULL, err, TEXT("Error"), MB_RETRYCANCEL | MB_ICONERROR, 0) == IDCANCEL)
			break;
	}
	return ret;
}
