// IniFile.cpp: implementation of the CIniFile class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "IniFile.h"
#include <vector>

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
		size_t  len;

		::GetModuleFileName(AfxGetApp()->m_hInstance, szAppName, _countof(szAppName));
		szAppName[_countof(szAppName) - 1] = _T('\0');
		len = _tcslen(szAppName);
		for(size_t i=len; i>0; i--)
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

namespace
{
	const DWORD kMaxIniCharacters = 1024 * 1024;
	BOOL ReadIniBuffer(const CString& path, LPCTSTR section, LPCTSTR key,
		LPCTSTR fallback, BOOL sections, BOOL wholeSection, std::vector<TCHAR>& buffer)
	{
		for (DWORD size = 512; size <= kMaxIniCharacters; size *= 2)
		{
			buffer.assign(size, 0);
			SetLastError(ERROR_SUCCESS);
			DWORD used = sections ? GetPrivateProfileSectionNames(&buffer[0], size, path) :
				(wholeSection ? GetPrivateProfileSection(section, &buffer[0], size, path) :
				 GetPrivateProfileString(section, key, fallback, &buffer[0], size, path));
			DWORD error = GetLastError();
			if (!used && error && error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
				return FALSE;
			const DWORD reserve = sections || wholeSection ? 2 : 1;
			if (used < size - reserve) return TRUE;
		}
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return FALSE;
	}
}

int CIniFile::GetSectionList(list<CString>& ls)
{
	std::vector<TCHAR> buffer;
	if (!ReadIniBuffer(IniFileName, NULL, NULL, NULL, TRUE, FALSE, buffer)) return -1;
	int count = 0;
	for (LPCTSTR item = &buffer[0]; *item; item += _tcslen(item) + 1)
	{
		ls.push_back(item);
		++count;
	}
	return count;
}

BOOL CIniFile::ReadSection(const CString& name, Section& values)
{
	std::vector<TCHAR> buffer;
	if (!ReadIniBuffer(IniFileName, name, NULL, NULL, FALSE, TRUE, buffer)) return FALSE;
	Section loaded;
	for (LPCTSTR item = &buffer[0]; *item; item += _tcslen(item) + 1)
	{
		LPCTSTR separator = _tcschr(item, L'=');
		if (separator) loaded[CString(item, static_cast<int>(separator - item))] = separator + 1;
	}
	values.swap(loaded);
	return TRUE;
}

BOOL CIniFile::WriteSection(const CString& name, const Section& values)
{
	std::vector<TCHAR> buffer;
	for (Section::const_iterator i = values.begin(); i != values.end(); ++i)
	{
		if (i->first.IsEmpty() || i->first.FindOneOf(L"=\r\n") >= 0 || i->second.FindOneOf(L"\r\n") >= 0)
		{ SetLastError(ERROR_INVALID_DATA); return FALSE; }
		CString line = i->first + L"=" + i->second;
		buffer.insert(buffer.end(), static_cast<LPCTSTR>(line), static_cast<LPCTSTR>(line) + line.GetLength() + 1);
	}
	buffer.push_back(0);
	if (values.empty()) buffer.push_back(0);
	// Preserve the XP whole-section limit (65535 bytes).
	if (buffer.size() * sizeof(TCHAR) > 65534) { SetLastError(ERROR_BUFFER_OVERFLOW); return FALSE; }
	return WritePrivateProfileSection(name, &buffer[0], IniFileName);
}

int CIniFile::GetKeyList(LPCTSTR name, list<CString>& ls)
{
	Section values;
	if (!ReadSection(name, values)) return -1;
	for (Section::const_iterator i = values.begin(); i != values.end(); ++i) ls.push_back(i->first);
	return static_cast<int>(values.size());
}

BOOL CIniFile::DeleteSection(CString AppName)
{
	return ::WritePrivateProfileString(AppName, 0, 0, IniFileName);
}

CString CIniFile::GetString(CString section, CString key, CString fallback)
{
	std::vector<TCHAR> buffer;
	return ReadIniBuffer(IniFileName, section, key, fallback, FALSE, FALSE, buffer) ? CString(&buffer[0]) : fallback;
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
