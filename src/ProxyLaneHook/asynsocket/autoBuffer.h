#if !defined _AUTOBUFFER
#define _AUTOBUFFER

#include <windows.h>

class autoBuffer
{
private:
	BYTE *m_buffer;
	DWORD size;
	DWORD maxsize;
public:
	autoBuffer();
	virtual ~autoBuffer();

	bool checkBufferSize(DWORD requiredSize, bool ReAlloc);
	operator BYTE*(){return m_buffer;};
	operator char*(){return (char*)m_buffer;};
	BYTE *operator +(int p){return m_buffer+p;};

	BYTE *GetBuffer(){ return m_buffer;}
	DWORD GetSize(){ return size;}

	DWORD LimiteMaxSize(DWORD max){
		maxsize = max;
		return maxsize;
	}
};


#endif