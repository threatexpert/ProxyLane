
#include "stdafx.h"
#include "autoBuffer.h"



autoBuffer::autoBuffer()
{
	m_buffer = NULL;
	size = 0;
	maxsize = 1024*1024*15;
}

autoBuffer::~autoBuffer()
{
	delete [] m_buffer;

}


//ReAlloc 标志是否保留原来的数据
bool autoBuffer::checkBufferSize(DWORD requiredSize, bool ReAlloc)
{
	if(size < requiredSize)
	{
		if(requiredSize > maxsize)
			return false;

		BYTE *tmp;
		tmp = new BYTE[requiredSize];
		if(tmp == NULL)
			return false;
		

		if(ReAlloc)
		{
			if(m_buffer == NULL)
			{
				memset(tmp, 0, requiredSize);
			}else
			{
				memcpy(tmp, m_buffer, size);
				delete [] m_buffer;
			}
			m_buffer = tmp;
			size = requiredSize;
			return true;
		}else
		{
			delete [] m_buffer;
			m_buffer = tmp;
			size = requiredSize;
			memset(m_buffer, 0, size);
			return true;
		}
	}

	return true;
}
