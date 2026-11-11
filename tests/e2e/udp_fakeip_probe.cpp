// Headless production-Hook regression probe. All outputs belong in build/qa.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <iostream>
#include <stdexcept>
#pragma comment(lib,"ws2_32.lib")
static void check(bool ok,const char* reason) {if(!ok)throw std::runtime_error(reason);}
int main(int argc,char** argv) {
    try {
        check(argc==3,"expected Hook DLL and PRC pipe");
        WSADATA wsa;check(!WSAStartup(MAKEWORD(2,2),&wsa),"WSAStartup");
        auto module=LoadLibraryA(argv[1]);check(module!=NULL,"load Hook");
        auto hook=(BOOL(WINAPI*)(LPCSTR))GetProcAddress(module,"gp_HookWinsock");
        check(hook&&hook(argv[2]),"install Hook");
        // Exercise actual intercepted DNS, not just a hardcoded FakeIP.
        addrinfo hints={},*resolved=nullptr;hints.ai_family=AF_INET;hints.ai_socktype=SOCK_DGRAM;
        check(!getaddrinfo("udp-block-regression.invalid","443",&hints,&resolved),"FakeIP DNS resolution");
        auto fake=((sockaddr_in*)resolved->ai_addr)->sin_addr;
        check((ntohl(fake.s_addr)>>16)==0x7fff,"DNS did not return FakeIP");
        freeaddrinfo(resolved);
        const char* targets[]={"127.255.0.1","127.255.255.254","::ffff:127.255.0.1","fdff::1","192.0.2.10","2001:db8::1"};
        int attempts=0;
        for(const char* target:targets) for(int api=0;api<5;++api) {
            sockaddr_storage address={};int family=strchr(target,':')?AF_INET6:AF_INET;
            int length=family==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6);
            if(family==AF_INET) {auto a=(sockaddr_in*)&address;a->sin_family=AF_INET;a->sin_port=htons(443);InetPtonA(AF_INET,target,&a->sin_addr);}
            else {auto a=(sockaddr_in6*)&address;a->sin6_family=AF_INET6;a->sin6_port=htons(443);InetPtonA(AF_INET6,target,&a->sin6_addr);}
            SOCKET s=socket(family,SOCK_DGRAM,IPPROTO_UDP);check(s!=INVALID_SOCKET,"UDP socket");
            if(family==AF_INET6){DWORD off=0;setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(char*)&off,sizeof(off));}
            char data='x';WSABUF b={1,&data};DWORD sent=0;int result=0;
            if(api==0)result=connect(s,(sockaddr*)&address,length);
            if(api==1)result=WSAConnect(s,(sockaddr*)&address,length,NULL,NULL,NULL,NULL);
            if(api==2)result=sendto(s,&data,1,0,(sockaddr*)&address,length);
            if(api==3)result=WSASendTo(s,&b,1,&sent,0,(sockaddr*)&address,length,NULL,NULL);
            if(api==4){GUID id=WSAID_WSASENDMSG;LPFN_WSASENDMSG fn=nullptr;DWORD n=0;
                check(!WSAIoctl(s,SIO_GET_EXTENSION_FUNCTION_POINTER,&id,sizeof(id),&fn,sizeof(fn),&n,NULL,NULL),"WSASendMsg pointer");
                WSAMSG msg={};msg.name=(sockaddr*)&address;msg.namelen=length;msg.lpBuffers=&b;msg.dwBufferCount=1;
                result=fn(s,&msg,0,&sent,NULL,NULL);
            }
            int error=WSAGetLastError();closesocket(s);
            std::cout<<target<<" api="<<api<<" result="<<result<<" error="<<error<<std::endl;
            check(result==SOCKET_ERROR&&error==WSAEACCES,"UDP destination was not blocked");++attempts;
        }
        // Genuine local UDP, including connected send and null-destination sendto.
        for(int family:{AF_INET,AF_INET6}) {
            SOCKET s=socket(family,SOCK_DGRAM,IPPROTO_UDP);check(s!=INVALID_SOCKET,"local UDP socket");
            sockaddr_storage address={};int length=family==AF_INET?sizeof(sockaddr_in):sizeof(sockaddr_in6);
            if(family==AF_INET){auto a=(sockaddr_in*)&address;a->sin_family=family;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);}
            else {auto a=(sockaddr_in6*)&address;a->sin6_family=family;a->sin6_addr=in6addr_loopback;}
            check(!bind(s,(sockaddr*)&address,length),"bind local UDP");check(!getsockname(s,(sockaddr*)&address,&length),"local UDP name");
            DWORD timeout=2000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
            check(!connect(s,(sockaddr*)&address,length),"local UDP connect");
            check(sendto(s,"x",1,0,NULL,0)==1,"local UDP sendto");char b=0;check(recv(s,&b,1,0)==1&&b=='x',"local UDP receive");
            check(send(s,"y",1,0)==1,"local UDP send");check(recv(s,&b,1,0)==1&&b=='y',"local UDP receive 2");closesocket(s);
        }
        // TCP retains the existing real-loopback bypass with UDP blocking enabled.
        SOCKET listener=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);sockaddr_in local={};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        check(!bind(listener,(sockaddr*)&local,sizeof(local))&&!listen(listener,1),"TCP listener");int length=sizeof(local);getsockname(listener,(sockaddr*)&local,&length);
        SOCKET client=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(!connect(client,(sockaddr*)&local,length),"TCP connect");
        SOCKET peer=accept(listener,NULL,NULL);check(peer!=INVALID_SOCKET,"TCP accept");check(send(client,"ok",2,0)==2,"TCP send");char b[2];check(recv(peer,b,2,MSG_WAITALL)==2,"TCP receive");
        closesocket(peer);closesocket(client);closesocket(listener);
        std::cout<<"PASS "<<attempts<<" blocked attempts; real DNS FakeIP; IPv4/IPv6 local UDP and TCP"<<std::endl;
        WSACleanup();return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<std::endl;return 1;}
}
