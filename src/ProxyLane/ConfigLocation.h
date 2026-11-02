#pragma once

namespace ConfigLocation
{
	// The one settings file every part of the application reads and writes.
	CString SettingsPath();
	// Creates the directory and default settings on first run, then keeps a
	// rolling backup. Call once at startup, before anything reads the settings.
	void PrepareStorage();
}
