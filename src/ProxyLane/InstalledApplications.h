#pragma once

#include <afxstr.h>
#include <vector>

namespace InstalledApplications
{
	enum SourceKind
	{
		SOURCE_SYSTEM_APPLICATIONS,
		SOURCE_USER_START_MENU,
		SOURCE_COMMON_START_MENU,
		SOURCE_SHORTCUT,
		SOURCE_SHELL_OBJECT
	};
	struct Source
	{
		SourceKind kind;
		CString path;
		Source(SourceKind sourceKind, const CString& sourcePath) : kind(sourceKind), path(sourcePath) {}
	};
	struct Application
	{
		CString name;
		CString path;
		CString aumid;
		CString arguments;
		CString workingDirectory;
		std::vector<Source> sources;
		HICON icon;
		Application() : icon(NULL) {}
		BOOL IsPackaged() const { return !aumid.IsEmpty(); }
	};

	// The caller initializes COM and owns the icons in the returned collection.
	HRESULT Enumerate(std::vector<Application>& applications, HANDLE cancelEvent);
	void ReleaseIcons(std::vector<Application>& applications);
	// Copies icon handles too; a dialog never owns the cache's icons.
	void Clone(const std::vector<Application>& source, std::vector<Application>& destination);
	// Merge equivalent launch entries, filling absent cwd metadata rather than
	// treating it as a different launch configuration. Retains icon ownership.
	void Deduplicate(std::vector<Application>& applications);
	// Ordinary targets are quoted EXE paths; packaged targets are activation IDs.
	CString LaunchTargetAndArguments(const Application& application);
	BOOL ResolveShortcut(LPCTSTR path, Application& application);
	// Accepts the Shell IDList Array used by virtual Start-menu app entries.
	// Invalid data is rejected before any item is launched. No icons are returned.
	BOOL ResolveShellDrop(HGLOBAL data, std::vector<Application>& applications);
}
