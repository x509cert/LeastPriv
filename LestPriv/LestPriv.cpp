// This sample code shows how to dynamically remove dangerous privileges and set the process to low integrity.
// Note that the code uses only std:wstring and std:vector from STL, 
// these instances could be replaced with other classes, 
// or plain C++ arrays and Unicode string pointers.
// 
// Author Michael Howard (mikehow@microsoft.com)
// Jan 3rd, 2023

#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>
#include "sal.h"

#pragma comment(lib, "advapi32.lib")


_Check_return_ bool RemovePrivileges(_In_ const std::vector<std::wstring> privsToRemove)
{
    if (privsToRemove.size() == 0)
    {
        return false;
    }
	
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        return false;
    }
	
    TOKEN_PRIVILEGES* pTokenPrivs = (TOKEN_PRIVILEGES*)malloc(sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * privsToRemove.size());
    if (!pTokenPrivs)
    {
        return false;
    }
	
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

    if (!fRes || !AdjustTokenPrivileges(hToken, FALSE, pTokenPrivs, sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * privsToRemove.size(), NULL, NULL))
    {
        fRes = false;
    }
	
    if (pTokenPrivs)
    {
        free(pTokenPrivs);
    }
	
    if (hToken)
    {
        CloseHandle(hToken);
    }
	
    return fRes;
}

_Check_return_ bool SetLowIntegrityLevel() {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
    {
        return false;
    }

    TOKEN_MANDATORY_LABEL integrityLabel{};
    PSID pSidIntgrityLabel = NULL;
    ConvertStringSidToSid(L"S-1-16-4096", &pSidIntgrityLabel);
    integrityLabel.Label.Attributes = SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED;
    integrityLabel.Label.Sid = pSidIntgrityLabel;

    bool fRes = true;
    DWORD dwTokenSize = 0;
    if (!GetTokenInformation(hToken, TokenIntegrityLevel, reinterpret_cast<LPVOID>(&integrityLabel), dwTokenSize, &dwTokenSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        fRes = false;
    }
	
    if (!fRes || !SetTokenInformation(hToken, TokenIntegrityLevel, reinterpret_cast<LPVOID>(&integrityLabel), dwTokenSize))
    {
        fRes = false;
    }
	
    if (pSidIntgrityLabel)
    {
        LocalFree(&pSidIntgrityLabel);
    }

    if (hToken)
    {
        CloseHandle(hToken);
    }

    return fRes;
}

void WriteToWindowsFolder() 
{
    FILE *pFile{};
    fopen_s(&pFile, "c:\\windows\\system32\\test.txt", "w");

    // Check if the file was successfully opened
    if (pFile == NULL) {
        perror("Could not open file");
        return;
    }

    // Write to the file
    const char* str = "This is a test.";
    fwrite(str, sizeof(char), strlen(str), pFile);

    // Close the file
    fclose(pFile);
}

int main() {

    // From https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    const std::vector<std::wstring> privs{ SE_BACKUP_NAME, SE_RESTORE_NAME, SE_TCB_NAME, SE_TAKE_OWNERSHIP_NAME, 
                                           SE_DEBUG_NAME, SE_IMPERSONATE_NAME,  SE_CREATE_GLOBAL_NAME, SE_CREATE_TOKEN_NAME, 
                                           SE_SECURITY_NAME, SE_RELABEL_NAME, SE_LOAD_DRIVER_NAME, SE_SYSTEMTIME_NAME };

    WriteToWindowsFolder();

    if (RemovePrivileges(privs) == false || SetLowIntegrityLevel() == false) 
    {
        printf("Failed to remove privileges or set low integrity level");
        return false;
    }

    return true;
}