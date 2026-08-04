// IniFile.cpp: implementation of the CIniFile class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "IniFile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif
#define MAX_LENGTH 256
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CIniFile::CIniFile()
{

}

CIniFile::~CIniFile()
{
	
}

void CIniFile::SetIniFileName(CString FileName)
{
	if (FileName.GetLength() > 0)
	{
		IniFileName = FileName;
	}else
	{
		TCHAR szAppName[MAX_PATH] = { 0 };
		int  len;

		::GetModuleFileName(AfxGetApp()->m_hInstance, szAppName, _countof(szAppName));
		szAppName[_countof(szAppName) - 1] = _T('\0');
		len = _tcslen(szAppName);
		for(int i=len; i>0; i--)
		{
			if(szAppName[i] == '.')
			{
				szAppName[i+1] = '\0';
				break;
			}
		}
		_tcscat(szAppName, _T("ini"));
		IniFileName = szAppName;
	}
}

DWORD SeparateSection(TCHAR *InPutBuf, TCHAR *ReturnString)
{
	DWORD len = 0;
	TCHAR *in = InPutBuf;
	TCHAR *out = ReturnString;

	while(*in && len < 128)
	{
		*out = *in;
		in++;
		out++;
		len++;
	}
	ReturnString[len] = '\0';
	return len;
}

int CIniFile::GetSectionList(list<CString> &ls)
{
	int nSize = 0;
	LPTSTR lpszReturnBuffer = NULL;
	DWORD ret;

	while (1)
	{
		ret = GetPrivateProfileSectionNames(lpszReturnBuffer, nSize, IniFileName);
		if (nSize - ret > 2)
			break;

		delete lpszReturnBuffer;
		nSize += 8192;
		lpszReturnBuffer = new TCHAR[nSize];
		lpszReturnBuffer[0] = '\0';
	}

	int n = 0;
	DWORD len;
	TCHAR szName[128];
	TCHAR *p = lpszReturnBuffer;
	while( len = SeparateSection(p, szName) )
	{
		p += len+1;
		n++;
		ls.push_back((CString)szName);
	}

	delete lpszReturnBuffer;
	return n;
}

int CIniFile::GetKeyList(LPCTSTR lpszAppName, list<CString> &ls)
{
	int nSize = 0;
	LPTSTR lpszReturnBuffer = NULL;
	DWORD ret;

	while (1)
	{
		ret = GetPrivateProfileSection(lpszAppName, lpszReturnBuffer, nSize, IniFileName);
		if (nSize - ret > 2)
			break;

		delete lpszReturnBuffer;
		nSize += 8192;
		lpszReturnBuffer = new TCHAR[nSize];
		lpszReturnBuffer[0] = '\0';
	}

	int n = 0;
	DWORD len;
	TCHAR szName[128];
	TCHAR *p = lpszReturnBuffer;
	while( len = SeparateSection(p, szName) )
	{
		p += len+1;
		TCHAR *pE = _tcschr(szName, '=');
		if (pE)
			*pE = '\0';
		n++;
		ls.push_back((CString)szName);
	}

	delete lpszReturnBuffer;
	return n;
}

BOOL CIniFile::DeleteSection(CString AppName)
{
	return ::WritePrivateProfileString(AppName, 0, 0, IniFileName);
}

CString CIniFile::GetString(CString AppName,CString KeyName,CString Default)
{
	TCHAR buf[MAX_LENGTH];
	DWORD dwRet;
	DWORD countofBuf = MAX_LENGTH;

	dwRet = ::GetPrivateProfileString(AppName, KeyName, Default, buf, countofBuf, IniFileName);
	if (dwRet < countofBuf-2)
	{
		return buf;
	}

	countofBuf = countofBuf+4096;
	for (;;)
	{
		CString str;
		TCHAR *p = str.GetBuffer(countofBuf);
		if (!p)
			return _T("");

		dwRet = ::GetPrivateProfileString(AppName, KeyName, Default, p, countofBuf, IniFileName);
		if (dwRet < countofBuf-2)
		{
			str.ReleaseBuffer(dwRet);
			return str;
		}
	}
}

int CIniFile::GetInt(CString AppName,CString KeyName,int Default)
{
	return ::GetPrivateProfileInt(AppName, KeyName, Default, IniFileName);
}

unsigned long CIniFile::GetDWORD(CString AppName,CString KeyName,unsigned long Default)
{
	TCHAR buf[MAX_LENGTH];
	CString temp;
	temp.Format(_T("%u"),Default);
	::GetPrivateProfileString(AppName, KeyName, temp, buf, sizeof(buf)/sizeof(buf[0])-1, IniFileName);
	return _tcstoul(buf, NULL, 0);
}

BOOL CIniFile::SetString(CString AppName,CString KeyName,CString Data)
{
	return ::WritePrivateProfileString(AppName, KeyName, Data, IniFileName);
}

BOOL CIniFile::SetInt(CString AppName,CString KeyName,int Data)
{
	CString temp;
	temp.Format(_T("%d"), Data);
	return ::WritePrivateProfileString(AppName, KeyName, temp, IniFileName);
}

BOOL CIniFile::SetDouble(CString AppName,CString KeyName,double Data)
{
	CString temp;
	temp.Format(_T("%f"),Data);
	return ::WritePrivateProfileString(AppName, KeyName, temp, IniFileName);
}

BOOL CIniFile::SetDWORD(CString AppName,CString KeyName,unsigned long Data)
{
	CString temp;
	temp.Format(_T("%u"),Data);
	return ::WritePrivateProfileString(AppName, KeyName, temp, IniFileName);
}

BOOL CIniFile::DeleteKeyName(LPCTSTR lpszAppName, LPCTSTR lpszKeyName)
{
	return ::WritePrivateProfileString(lpszAppName, lpszKeyName, NULL, IniFileName);
}
