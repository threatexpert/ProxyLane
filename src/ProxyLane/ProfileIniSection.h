#pragma once

#include <afxstr.h>

namespace ProfileIniSection
{
	constexpr wchar_t ProfilePrefix[] = L"proxy_";
	constexpr wchar_t EscapeMarker[] = L"~PLc~";
	constexpr int ProfilePrefixLength = _countof(ProfilePrefix) - 1;
	constexpr int EscapeMarkerLength = _countof(EscapeMarker) - 1;
	constexpr int EscapeLength = EscapeMarkerLength + 2;

	inline bool IsProfileSection(const CString& section)
	{
		return section.Left(ProfilePrefixLength).CompareNoCase(ProfilePrefix) == 0;
	}

	inline bool IsValidName(const CString& name)
	{
		return !name.IsEmpty() && name.FindOneOf(L"\r\n") < 0;
	}

	inline bool HasEscapeMarker(const CString& text, int offset)
	{
		return text[offset] == L'~' && text.Mid(offset, EscapeMarkerLength).CompareNoCase(EscapeMarker) == 0;
	}

	inline CString ToReference(const CString& name)
	{
		CString reference;
		for (int i = 0; i < name.GetLength(); ++i)
		{
			if (name[i] == L']')
			{
				reference += EscapeMarker;
				reference += L"5D";
			}
			else if (HasEscapeMarker(name, i))
			{
				reference += name.Mid(i, EscapeMarkerLength);
				reference += L"00";
				i += EscapeMarkerLength - 1;
			}
			else
				reference += name[i];
		}
		return reference;
	}

	inline CString FromReference(const CString& reference)
	{
		CString name;
		for (int i = 0; i < reference.GetLength(); ++i)
		{
			if (i + EscapeLength <= reference.GetLength() && HasEscapeMarker(reference, i))
			{
				const CString code = reference.Mid(i + EscapeMarkerLength, 2);
				if (code.CompareNoCase(L"5D") == 0)
				{
					name += L']';
					i += EscapeLength - 1;
					continue;
				}
				if (code == L"00")
				{
					name += reference.Mid(i, EscapeMarkerLength);
					i += EscapeLength - 1;
					continue;
				}
			}
			name += reference[i];
		}
		return name;
	}

	inline CString FromName(const CString& name)
	{
		return ProfilePrefix + ToReference(name);
	}

	inline CString ToName(const CString& section)
	{
		if (!IsProfileSection(section)) return CString();
		const CString reference = section.Mid(ProfilePrefixLength);
		if (!IsValidName(reference) || reference.Find(L']') >= 0) return CString();
		return FromReference(reference);
	}
}
