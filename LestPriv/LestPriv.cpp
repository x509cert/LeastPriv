#include <windows.h>
#include <sddl.h>
#include "sal.h"

#pragma comment(lib, "advapi32.lib")

bool RemovePrivilege(_In_z_ LPCWSTR privilege) {
    HANDLE hToken{};
    BOOL retVal = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

    LUID luid{};
    retVal = LookupPrivilegeValue(NULL, privilege, &luid);

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    retVal = AdjustTokenPrivileges(hToken, false, &tp, 0, NULL, NULL);
    return retVal;
}

bool SetLowIntegrityLevel() {
    HANDLE hToken{};
    BOOL retVal = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

    TOKEN_MANDATORY_LABEL mandatoryLabel{};
    PSID pSidIL = NULL;
    ConvertStringSidToSid(L"S-1-16-4096", &pSidIL);
    mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    mandatoryLabel.Label.Sid = pSidIL;

    DWORD dwTokenSize = 0;
    retVal = GetTokenInformation(hToken, TokenIntegrityLevel, (LPVOID)&mandatoryLabel, dwTokenSize, &dwTokenSize);
    retVal = SetTokenInformation(hToken, TokenIntegrityLevel, (LPVOID)&mandatoryLabel, dwTokenSize);

    if (pSidIL) free(pSidIL);

    return retVal;
}

void main() {
    RemovePrivilege(SE_SHUTDOWN_NAME);
    SetLowIntegrityLevel();
}