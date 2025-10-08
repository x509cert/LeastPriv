// Michael Howard (mikehow@microsoft.com)
// Microsoft Red Team
// Oct 7th, 2025

// This code demonstrates how to reduce the privileges and integrity level of the current process on Windows.

#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>
#include "sal.h"
#include <memory>

#pragma comment(lib, "advapi32.lib")

const size_t MAX_PRIVILEGE_COUNT = 34;

_Check_return_ bool RemovePrivileges(_In_ const std::vector<std::wstring> &privsToRemove)
{
    if (privsToRemove.size() == 0 || privsToRemove.size() >= MAX_PRIVILEGE_COUNT)
        return false;
	
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        return false;
	
    size_t bufferSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * (privsToRemove.size() - 1);
    std::unique_ptr<char[]> buffer(new char[bufferSize]);
    TOKEN_PRIVILEGES* pTokenPrivs = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.get());

    if (!pTokenPrivs)
        return false;
	
    pTokenPrivs->PrivilegeCount = privsToRemove.size();

    bool fRes = true;

    for (int i = 0; i < privsToRemove.size(); i++)
    {
        if (!LookupPrivilegeValue(NULL, privsToRemove[i].c_str(), &pTokenPrivs->Privileges[i].Luid))
        {
            fRes = false;
            break;
        }

        pTokenPrivs->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    }

    if (!fRes || !AdjustTokenPrivileges(hToken, FALSE, pTokenPrivs, bufferSize, NULL, NULL))
        fRes = false;
	
    if (hToken)
        CloseHandle(hToken);
	
    return fRes;
}

_Check_return_ bool SetLowIntegrityLevel() 
{
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
        return false;

    TOKEN_MANDATORY_LABEL integrityLabel{};
    SID sidLowIntegrity = {
      SID_REVISION, 1,
      {SECURITY_MANDATORY_LABEL_AUTHORITY},
      SECURITY_MANDATORY_LOW_RID };
    integrityLabel.Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    integrityLabel.Label.Sid = &sidLowIntegrity;

    bool fRes = true;
    DWORD dwTokenSize = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, reinterpret_cast<LPVOID>(&integrityLabel), dwTokenSize, &dwTokenSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        fRes = false;
	
    if (!fRes || !SetTokenInformation(hToken, TokenIntegrityLevel, reinterpret_cast<LPVOID>(&integrityLabel), dwTokenSize))
        fRes = false;

    if (hToken)
        CloseHandle(hToken);

    return fRes;
}

int main() {

    // From https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants and winnt.h
    const std::vector<std::wstring> privs{ SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TCB_NAME, SE_TAKE_OWNERSHIP_NAME, 
                                           SE_DEBUG_NAME, SE_IMPERSONATE_NAME,  SE_CREATE_GLOBAL_NAME, SE_CREATE_TOKEN_NAME, 
                                           SE_SECURITY_NAME, SE_RELABEL_NAME, SE_LOAD_DRIVER_NAME, SE_SYSTEMTIME_NAME};
    
    // reduce privilege and integrity level
    if (RemovePrivileges(privs) == false || SetLowIntegrityLevel() == false) {
        printf("Failed to remove privileges or set low integrity level, err==%d", GetLastError());
        return false;
    }

    return true;
}