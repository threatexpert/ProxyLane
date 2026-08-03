/*
Module : Base64.cpp
Purpose: Implementation for a simple base64 decoding class
Created: PJN / 22-04-1999
History: None

Copyright (c) 1999 - 2004 by PJ Naughter.

All rights reserved.

Copyright / Usage Details:

You are allowed to include the source code in any product (commercial, shareware, freeware or otherwise)
when your product is released in binary form. You are allowed to modify the source code in any way you want
except you cannot modify the copyright details at the top of each module. If you want to distribute source
code with your application, then you are only allowed to distribute versions released by the author. This is
to maintain a single distribution point for the source code.

*/



//////////////// Includes ////////////////////////////////////////////

#include "stdafx.h"
#include "Base64.h"

#if defined(__INTEL_COMPILER)
// remark #279: controlling expression is constant
#pragma warning(disable: 279)
#endif  // __INTEL_COMPILER

//////////////// Statics / Macros ////////////////////////////////////

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


char *s_chBase64EncodingTable = ("CkEzO+J/X61itgSsvmoVT9nAeBqYNhMLD0U3uy8GbjQ2RHZFfWrc5PIwaxlp47Kd");
char *s_chBase64EncodingTable_std = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");

CBase64::CBase64(BOOL bStd/* =TRUE */)
{
	if (bStd)
	{
		m_table = s_chBase64EncodingTable_std;
	}else
	{
		m_table = s_chBase64EncodingTable;
	}
}

//////////////// Implementation //////////////////////////////////////

int CBase64::DecodeGetRequiredLength(int nSrcLen)
{
        return nSrcLen;
}

int CBase64::EncodeGetRequiredLength(int nSrcLen, DWORD dwFlags)
{
        int nRet = nSrcLen*4/3;

        if ((dwFlags & BASE64_FLAG_NOPAD) == 0)
                nRet += nSrcLen % 3;

        int nCRLFs = nRet / 76 + 1;
        int nOnLastLine = nRet % 76;

        if (nOnLastLine)
        {
                if (nOnLastLine % 4)
                        nRet += 4-(nOnLastLine % 4);
        }

        nCRLFs *= 2;

        if ((dwFlags & BASE64_FLAG_NOCRLF) == 0)
                nRet += nCRLFs;

        return nRet;
}

BOOL CBase64::Encode(const BYTE* pbSrcData, int nSrcLen,        LPSTR szDest,   int* pnDestLen, DWORD dwFlags)
{
//         static const char s_chBase64EncodingTable[64] =
//   {
//                 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
//                 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
//                 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
//                 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

  //Validate our parameters
        if (!pbSrcData || !szDest || !pnDestLen)
                return FALSE;

        ASSERT(*pnDestLen >= EncodeGetRequiredLength(nSrcLen, dwFlags));

        int nWritten( 0 );
        int nLen1( (nSrcLen/3)*4 );
        int nLen2( nLen1/76 );
        int nLen3( 19 );

        for (int i=0; i<=nLen2; i++)
        {
                if (i==nLen2)
                        nLen3 = (nLen1%76)/4;

                for (int j=0; j<nLen3; j++)
                {
                        DWORD dwCurr(0);
                        for (int n=0; n<3; n++)
                        {
                                dwCurr |= *pbSrcData++;
                                dwCurr <<= 8;
                        }
                        for (int k=0; k<4; k++)
                        {
                                BYTE b = (BYTE)(dwCurr>>26);
                                *szDest++ = m_table[b];
                                dwCurr <<= 6;
                        }
                }
                nWritten+= nLen3*4;

                if ((dwFlags & BASE64_FLAG_NOCRLF)==0)
                {
                        *szDest++ = '\r';
                        *szDest++ = '\n';
                        nWritten+= 2;
                }
        }

        if (nWritten && (dwFlags & BASE64_FLAG_NOCRLF)==0)
        {
                szDest-= 2;
                nWritten -= 2;
        }

        nLen2 = nSrcLen%3 ? nSrcLen%3 + 1 : 0;
        if (nLen2)
        {
                DWORD dwCurr(0);
                for (int n=0; n<3; n++)
                {
                        if (n<(nSrcLen%3))
                                dwCurr |= *pbSrcData++;
                        dwCurr <<= 8;
                }
                for (int k=0; k<nLen2; k++)
                {
                        BYTE b = (BYTE)(dwCurr>>26);
                        *szDest++ = m_table[b];
                        dwCurr <<= 6;
                }
                nWritten+= nLen2;
                if ((dwFlags & BASE64_FLAG_NOPAD)==0)
                {
                        nLen3 = nLen2 ? 4-nLen2 : 0;
                        for (int j=0; j<nLen3; j++)
                        {
                                *szDest++ = '=';
                        }
                        nWritten+= nLen3;
                }
        }

        *pnDestLen = nWritten;
        return TRUE;
}

int CBase64::DecodeChar(unsigned int ch)
{


	for (int i=0; i<64; i++)
	{
		if (ch == m_table[i])
			return i;
	}

	return -1;
}

BOOL CBase64::Decode(LPCSTR szSrc, int nSrcLen, BYTE *pbDest, int *pnDestLen)
{
        // walk the source buffer
        // each four character sequence is converted to 3 bytes
        // CRLFs and =, and any characters not in the encoding table
        // are skiped

  //Validate our parameters
        if (!szSrc || !pbDest || !pnDestLen)
                return FALSE;

        LPCSTR szSrcEnd = szSrc + nSrcLen;
        int nWritten = 0;
        while (szSrc < szSrcEnd)
        {
                DWORD dwCurr = 0;
                int i;
                int nBits = 0;
                for (i=0; i<4; i++)
                {
                        if (szSrc >= szSrcEnd)
                                break;
                        int nCh = DecodeChar(*szSrc);
                        szSrc++;
                        if (nCh == -1)
                        {
                                // skip this char
                                i--;
                                continue;
                        }
                        dwCurr <<= 6;
                        dwCurr |= nCh;
                        nBits += 6;
                }
                // dwCurr has the 3 bytes to write to the output buffer
                // left to right
                dwCurr <<= 24-nBits;
                for (i=0; i<nBits/8; i++)
                {
                        *pbDest = (BYTE) ((dwCurr & 0x00ff0000) >> 16);
                        dwCurr <<= 8;
                        pbDest++;
                        nWritten++;
                }
        }

        *pnDestLen = nWritten;
        return TRUE;
}

BOOL CBase64::DecodeW(LPCWSTR szSrc, int nSrcLen, BYTE *pbDest, int *pnDestLen)
{
        // walk the source buffer
        // each four character sequence is converted to 3 bytes
        // CRLFs and =, and any characters not in the encoding table
        // are skiped

  //Validate our parameters
        if (!szSrc || !pbDest || !pnDestLen)
                return FALSE;

        LPCWSTR szSrcEnd = szSrc + nSrcLen;
        int nWritten = 0;
        while (szSrc < szSrcEnd)
        {
                DWORD dwCurr = 0;
                int i;
                int nBits = 0;
                for (i=0; i<4; i++)
                {
                        if (szSrc >= szSrcEnd)
                                break;
                        int nCh = DecodeChar(*szSrc);
                        szSrc++;
                        if (nCh == -1)
                        {
                                // skip this char
                                i--;
                                continue;
                        }
                        dwCurr <<= 6;
                        dwCurr |= nCh;
                        nBits += 6;
                }
                // dwCurr has the 3 bytes to write to the output buffer
                // left to right
                dwCurr <<= 24-nBits;
                for (i=0; i<nBits/8; i++)
                {
                        *pbDest = (BYTE) ((dwCurr & 0x00ff0000) >> 16);
                        dwCurr <<= 8;
                        pbDest++;
                        nWritten++;
                }
        }

        *pnDestLen = nWritten;
        return TRUE;
}
