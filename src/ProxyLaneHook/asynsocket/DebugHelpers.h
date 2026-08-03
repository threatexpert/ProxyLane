#pragma once

#define CHECK_OBJ(pObj)		if (pObj != NULL) ASSERT_VALID(pObj)
#define CHECK_PTR(ptr)		ASSERT( ptr == NULL || AfxIsValidAddress(ptr, sizeof(*ptr)) );
#define CHECK_ARR(ptr, len)	ASSERT( (ptr == NULL && len == 0) || (ptr != NULL && len != 0 && AfxIsValidAddress(ptr, len)) );
#define	CHECK_BOOL(bVal)	ASSERT( (UINT)(bVal) == 0 || (UINT)(bVal) == 1 );

#define	CRASH_HERE()		(*((int*)NULL) = 0)


//#ifdef _DEBUG
//#ifndef NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER
#define NO_USE_CLIENT_TCP_CATCH_ALL_HANDLER	1
//#endif
//#endif


#ifndef _AFX
#ifndef VERIFY
#define VERIFY(x) (void(x))
#endif //VERIFY
#endif //_AFX
