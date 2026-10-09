// IniFile.h: interface for the CIniFile class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_INIFILE_H__D5A2B7FC_6022_4EA2_9E54_91C4E7B31B8E__INCLUDED_)
#define AFX_INIFILE_H__D5A2B7FC_6022_4EA2_9E54_91C4E7B31B8E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <map>

class CIniFile  
{
public:
	struct KeyLess { bool operator()(const CString& a, const CString& b) const { return a.CompareNoCase(b) < 0; } };
	typedef std::map<CString, CString, KeyLess> Section;
	BOOL ReadSection(const CString& name, Section& values);
	BOOL WriteSection(const CString& name, const Section& values);
	CIniFile();
	virtual ~CIniFile();
	void	SetIniFileName(CString FileName);
	CString	GetIniFileName(){ return IniFileName; }

	int GetSectionList(list<CString> &ls);
	BOOL DeleteSection(CString AppName);
	CString	GetString(CString AppName, CString KeyName, CString Default = _T(""));
	int		GetInt(CString AppName, CString KeyName, int Default = 0);
	unsigned long	GetDWORD(CString AppName, CString KeyName, unsigned long Default = 0);
	
	int GetKeyList(LPCTSTR lpszAppName, list<CString> &ls);
	BOOL    DeleteKeyName(LPCTSTR lpszAppName, LPCTSTR lpszKeyName);
	BOOL	SetString(CString AppName, CString KeyName, CString Data);
	BOOL	SetInt(CString AppName, CString KeyName, int Data);
	BOOL	SetDouble(CString AppName, CString KeyName, double Data);
	BOOL	SetDWORD(CString AppName, CString KeyName, unsigned long Data);
private:
	CString IniFileName;
};

#endif // !defined(AFX_INIFILE_H__D5A2B7FC_6022_4EA2_9E54_91C4E7B31B8E__INCLUDED_)
