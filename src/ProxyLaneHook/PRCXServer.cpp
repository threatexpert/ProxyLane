#include "stdafx.h"
#include "PRCXServer.h"
#include "ProxyReceptionCentre.h"

CPRCXServer::CPRCXServer(CProxyReceptionCentre *pPRC)
{
	m_pPRC = pPRC;
	m_pGlobalProxy = pPRC->m_pGlobalProxy;
}

CPRCXServer::~CPRCXServer(void)
{

}