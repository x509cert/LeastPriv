#include <windows.h>
#include <sddl.h>
#include "sal.h"

#pragma comment(lib, "advapi32.lib")

bool RemovePrivilege(_In_z_ LPCWSTR privilege) {
    HANDLE hToken{};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		return false;
	}

    LUID luid{};
	if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
		CloseHandle(hToken);
		return false;
	}   

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

	if (!AdjustTokenPrivileges(hToken, false, &tp, 0, NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}

    return true;
}

bool SetLowIntegrityLevel() {
    HANDLE hToken{};
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		return false;
	}

    TOKEN_MANDATORY_LABEL integrityLabel{};
    PSID pSidIL = NULL;
    ConvertStringSidToSid(L"S-1-16-4096", &pSidIL);
    integrityLabel.Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    integrityLabel.Label.Sid = pSidIL;

    DWORD dwTokenSize = 0;
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, (LPVOID)&integrityLabel, dwTokenSize, &dwTokenSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        if (pSidIL) free(pSidIL);
        return false;
    }
	
    if (!SetTokenInformation(hToken, TokenIntegrityLevel, (LPVOID)&integrityLabel, dwTokenSize)) {
        if (pSidIL) free(pSidIL);
        return false;
    }
	
    if (pSidIL) free(pSidIL);

    return true;
}

void main() {
    RemovePrivilege(SE_SHUTDOWN_NAME);
    SetLowIntegrityLevel();
}