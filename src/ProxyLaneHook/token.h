#pragma once
#include <Aclapi.h>

BOOL GrantPrivilege(TCHAR *PName, BOOL bEnable);
PSID GetSid(LPCTSTR lpAccountName, PSID_NAME_USE peUse);
BOOL CopySecurityDescriptorDaclAccess(PSECURITY_DESCRIPTOR pFromSD, PSECURITY_DESCRIPTOR pToSD);
BOOL SetSecurityDescriptorDaclAccess(PSECURITY_DESCRIPTOR pSD, LPCTSTR pUserName, DWORD AccessPermissions, ACCESS_MODE AccessMode, DWORD Inheritance, PACL * ppNewAcl);

BOOL ApplySD2LowIntegrity(PSECURITY_DESCRIPTOR lpSecurityDescriptor);
BOOL IsVistaOrLater();

class CSecurityAttributes : public SECURITY_ATTRIBUTES
{
public:
	PACL m_pNewDAcl;
	PSECURITY_DESCRIPTOR m_pLowIntegritySD;

public:
	CSecurityAttributes(BOOL bInheritHandle = FALSE);
	~CSecurityAttributes();

	BOOL CreateSD(LPCTSTR lpUserName, DWORD dwAcc, DWORD Inheritance, DWORD AccessMode=SET_ACCESS);
	BOOL LowIntegrity();
	BOOL SetSDDacl(LPCTSTR pUserName, DWORD AccessPermissions, ACCESS_MODE AccessMode, DWORD Inheritance);
};