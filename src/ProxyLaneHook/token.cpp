#include "stdafx.h"
#include "token.h"

#include <accctrl.h>
#include <Sddl.h>
#include <Aclapi.h>

BOOL GrantPrivilege(TCHAR *PName, BOOL bEnable)
{
	BOOL              bResult = TRUE;
	HANDLE            hToken;
	TOKEN_PRIVILEGES  TokenPrivileges;
	
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,&hToken) == 0)
	{
		return FALSE;
	}
	TokenPrivileges.PrivilegeCount           = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	LookupPrivilegeValue(NULL,PName,&TokenPrivileges.Privileges[0].Luid);
	bResult = AdjustTokenPrivileges(hToken,FALSE,&TokenPrivileges,sizeof(TOKEN_PRIVILEGES),NULL,NULL);
    if(!bResult || GetLastError()!=ERROR_SUCCESS)
	{
		bResult = FALSE;
	}
	CloseHandle(hToken);
    
	return bResult;
}

/*
PSID GetSid(LPCTSTR lpAccountName, PSID_NAME_USE peUse)
{
	PSID pSid = NULL;
	DWORD cbSid = 0;
	TCHAR ReferencedDomainName[MAX_PATH];
	DWORD cchReferencedDomainName = sizeof(ReferencedDomainName);
	SID_NAME_USE us;
	BOOL bOK;

	bOK = LookupAccountName(NULL,
		lpAccountName,
		pSid,
		&cbSid,
		ReferencedDomainName,
		&cchReferencedDomainName,
		peUse ? peUse : &us
		);

	pSid = (PSID) LocalAlloc(LPTR, cbSid); 

	bOK = LookupAccountName(NULL,
		lpAccountName,
		pSid,
		&cbSid,
		ReferencedDomainName,
		&cchReferencedDomainName,
		peUse ? peUse : &us
		);

	if (!bOK)
	{
		LocalFree(pSid);
		return NULL;
	}

	return pSid;
}
*/

BOOL CopySecurityDescriptorDaclAccess(PSECURITY_DESCRIPTOR pFromSD, PSECURITY_DESCRIPTOR pToSD)
{
	BOOL                 bDaclPresent   = FALSE;
	BOOL                 bDaclDefaulted = FALSE;
	DWORD                dwError        = 0;
	PACL                 pacl           = NULL;
	BOOL bRet = FALSE;

	if (!GetSecurityDescriptorDacl(pFromSD, &bDaclPresent, &pacl,
		&bDaclDefaulted))
	{
		dwError = GetLastError();
		goto __Cleanup;
	}
	
	if (!SetSecurityDescriptorDacl(pToSD, TRUE, pacl, FALSE))
	{
		dwError = GetLastError();
		goto __Cleanup;
	}
	
	bRet = IsValidSecurityDescriptor(pToSD);
	
	return bRet;
__Cleanup:
	
	SetLastError(dwError);
	
	return bRet;
}

BOOL SetSecurityDescriptorDaclAccess(PSECURITY_DESCRIPTOR pSD, LPCTSTR pUserName, DWORD AccessPermissions, ACCESS_MODE AccessMode, DWORD Inheritance, PACL * ppNewAcl /*= NULL*/)
{
	BOOL                 bDaclPresent   = FALSE;
	BOOL                 bDaclDefaulted = FALSE;
	DWORD                dwError        = 0;
	DWORD                dwSize         = 0;
	EXPLICIT_ACCESS      ea;
	PACL                 pacl           = NULL;
	PACL                 pNewAcl        = NULL;
	PSECURITY_DESCRIPTOR psd            = NULL;
	BOOL bRet = FALSE;
	TCHAR          szUser[128];
	//ACL_SIZE_INFORMATION aclsi;

	lstrcpyn(szUser, pUserName, sizeof(szUser));
	*ppNewAcl = NULL;

	// Get the DACL.
	if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pacl,
		&bDaclDefaulted))
	{
		dwError = GetLastError();
		goto __Cleanup;
	}
// 
// 	if (pacl && AccessMode == GRANT_ACCESS)
// 	{
// 		if (!GetAclInformation(pacl, &aclsi, sizeof(aclsi), AclSizeInformation))
// 		{
// 			dwError = GetLastError();
// 			goto __Cleanup;
// 		}
// 
// 		for (int i=0; i<aclsi.AceCount; i++)
// 		{
// 			ACCESS_DENIED_ACE *phACE = NULL;
// 			if (GetAce(pacl, i, (LPVOID *)&phACE))
// 			{
// 				if (phACE->Header.AceType == ACCESS_DENIED_ACE_TYPE)
// 				{
// 					if (phACE->Mask & AccessPermissions)
// 					{
// 						PSID pSid = (PSID)phACE->SidStart;
// 					}
// 				}
// 			}
// 		}
// 	}

	// Build the ACE.
	BuildExplicitAccessWithName(&ea, szUser,
		AccessPermissions,
		AccessMode, Inheritance);


	dwError = SetEntriesInAcl(1, &ea, pacl, &pNewAcl);
	if (dwError != ERROR_SUCCESS)
		goto __Cleanup;

	*ppNewAcl = pNewAcl;

	// Set the new DACL in the Security Descriptor.
	if (!SetSecurityDescriptorDacl(pSD, TRUE, pNewAcl, FALSE))
	{
		dwError = GetLastError();
		goto __Cleanup;
	}

	bRet = IsValidSecurityDescriptor(pSD);

	return bRet;
__Cleanup:

	SetLastError(dwError);

	return bRet;
}

BOOL IsVistaOrLater()
{
	OSVERSIONINFO osvi;
	BOOL bIsVistaOrLater;

	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	bIsVistaOrLater =       
		( (osvi.dwMajorVersion > 6) ||
		( (osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 0) ));

	return bIsVistaOrLater;
}

BOOL ApplySD2LowIntegrity(PSECURITY_DESCRIPTOR lpSecurityDescriptor, PSECURITY_DESCRIPTOR *llpNewSD)
{
	PSECURITY_DESCRIPTOR pLowIntegritySecDesc = NULL;
	PACL pAcl = NULL;
	BOOL fAclPresent = FALSE;
	BOOL fAclDefaulted = FALSE;
	BOOL bRetval = FALSE;

	*llpNewSD = NULL;

	if (!IsVistaOrLater())
		return FALSE;

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(_T("S:(ML;;NW;;;LW)"), // "low integrity"
		SDDL_REVISION_1, &pLowIntegritySecDesc, NULL))
		goto __RET;
	
	if (!SetSecurityDescriptorDacl(lpSecurityDescriptor, TRUE, 0, FALSE))
		goto __RET;

	if (!GetSecurityDescriptorSacl(pLowIntegritySecDesc, &fAclPresent, &pAcl, &fAclDefaulted))
		goto __RET;

	if (!SetSecurityDescriptorSacl(lpSecurityDescriptor, TRUE, pAcl, FALSE))
		goto __RET;

	bRetval = TRUE;

__RET:

	*llpNewSD = (pLowIntegritySecDesc);

	return bRetval;
}


///////////////////////////////////////////////////////////////////////////
//
//
//////////////////////////////////////////////////////////////////////////

CSecurityAttributes::CSecurityAttributes(BOOL bInheritHandle /*= FALSE*/)
{
	this->nLength = sizeof (SECURITY_ATTRIBUTES);
	this->lpSecurityDescriptor = NULL;
	this->bInheritHandle = bInheritHandle;
	
	m_pNewDAcl = NULL;
	m_pLowIntegritySD = NULL;
}

CSecurityAttributes::~CSecurityAttributes()
{
	if (m_pNewDAcl)
	{
		LocalFree(m_pNewDAcl);
	}
	if (this->lpSecurityDescriptor)
	{
		LocalFree(this->lpSecurityDescriptor);
	}
	if (m_pLowIntegritySD)
	{
		LocalFree(m_pLowIntegritySD);
	}
}

BOOL CSecurityAttributes::CreateSD(LPCTSTR lpUserName, DWORD dwAcc, DWORD Inheritance, DWORD AccessMode/*=SET_ACCESS*/)
{
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD			cbSid = 0;
	PACL           pACL = NULL;
	
	// Default
	// Initialize a security descriptor. 
	pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 
	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
	{
		LocalFree(pSD);
		return FALSE;
	}
	
	if (lpUserName)
	{
		if (!SetSecurityDescriptorDaclAccess(pSD, lpUserName, dwAcc, (ACCESS_MODE)AccessMode, Inheritance, &m_pNewDAcl))
		{
			LocalFree(pSD);
			return FALSE;
		}
	}
	
	this->lpSecurityDescriptor = pSD;
	
	return TRUE;
	
}

BOOL CSecurityAttributes::LowIntegrity()
{
	if (this->lpSecurityDescriptor == NULL)
	{
		return FALSE;
	}

	return ApplySD2LowIntegrity(this->lpSecurityDescriptor, &m_pLowIntegritySD);
}

BOOL CSecurityAttributes::SetSDDacl(LPCTSTR pUserName, DWORD AccessPermissions, ACCESS_MODE AccessMode, DWORD Inheritance)
{
	if (this->lpSecurityDescriptor == NULL){
		return FALSE;
	}

	PACL pNewDAcl = NULL;
	BOOL b = SetSecurityDescriptorDaclAccess(this->lpSecurityDescriptor, pUserName, AccessPermissions, (ACCESS_MODE)AccessMode, Inheritance, &pNewDAcl);
	if (b){
		if (m_pNewDAcl){
			LocalFree(m_pNewDAcl);
		}
		m_pNewDAcl = pNewDAcl;
	}else{
		if (pNewDAcl){
			LocalFree(pNewDAcl);
		}
	}
	return b;
}

