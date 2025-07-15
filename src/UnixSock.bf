namespace Beef_Net;
using System;

#if BF_PLATFORM_LINUX || BF_PLATFORM_MACOS
public typealias sa_family_t = uint16;

[CRepr, Union, Packed]
public struct in_addr
{
	public uint32 s_addr;
	public uint8[4] s_bytes;
}

[CRepr, Union, Packed]
public struct in6_addr
{
	public uint8[16] u6_addr8;
	public uint16[8] u6_addr16;
	public uint32[4] u6_addr32;
	public int8[16] s6_addr8;
	public int8[16] s6_addr;
	public int16[8] s6_addr16;
	public int32[4] s6_addr32;

	public this()
	{
		s6_addr32 = .(0, 0, 0, 0);
	}

	public this(SockAddr aAddr)
	{
		u6_addr8 = .(
			(uint8)(aAddr.sa_family & 0xFFU),
			(uint8)(aAddr.sa_family >> 8),
			aAddr.sa_data[0],
			aAddr.sa_data[1],
			aAddr.sa_data[2],
			aAddr.sa_data[3],
			aAddr.sa_data[4],
			aAddr.sa_data[5],
			aAddr.sa_data[6],
			aAddr.sa_data[7],
			aAddr.sa_data[8],
			aAddr.sa_data[9],
			aAddr.sa_data[10],
			aAddr.sa_data[11],
			aAddr.sa_data[12],
			aAddr.sa_data[13]
		);
	}
}

[CRepr, Packed]
public struct sockaddr_in
{
	  public sa_family_t sin_family; // Address family
	  public uint16 sin_port;        // Port
	  public in_addr sin_addr;       // IPV6 address
	  public uint8[8] xpad;
}

[CRepr, Packed]
public struct sockaddr_in6
{
	  public sa_family_t sin6_family; // Address family
	  public uint16 sin6_port;        // Port
	  public uint32 sin6_flowinfo;    // Flow information.
	  public in6_addr sin6_addr;      // IPV6 address
	  public uint32 sin6_scope_id;
}

[CRepr]
public struct AddrInfo
{
	public int ai_flags;
	public int ai_family;
	public int ai_socktype;
	public int ai_protocol;
	public uint ai_addrlen;
	public char8* ai_canonname;
	public SockAddr* ai_addr;
	public AddrInfo* ai_next;
}

[CRepr]
public struct HostEnt
{
	public char8* h_name;       // official name of host
	public char8** h_aliases;   // alias list
	public int16 h_addrtype;    // host address type
	public int16 h_length;      // length of address
	public uint8** h_addr_list; // list of addresses
}

[CRepr]
public struct TimeVal
{
	public int64 tv_sec;  // seconds
	public int64 tv_usec; // and microseconds
}

public typealias fd_handle = int32;

sealed static class UnixSock
{
    [CLink, CallingConvention(.Stdcall)]
    public extern static HostEnt* gethostbyname(char8* name);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 getaddrinfo(char8* pNodeName, char8* pServiceName, AddrInfo* pHints, AddrInfo** ppResult);

    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 getpeername(fd_handle sockfd, SockAddr* addr, int32* addrlen);

    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 getsockname(fd_handle sockfd, SockAddr* addr, int32* addrlen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static fd_handle socket(int32 af, int32 type, int32 protocol);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 connect(fd_handle s, SockAddr* name, int32 nameLen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 close(fd_handle s);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 bind(fd_handle s, SockAddr* name, int32 nameLen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 listen(fd_handle s, int32 backlog);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static fd_handle accept(fd_handle s, SockAddr* addr, int32* addrLen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 ioctl(fd_handle s, int cmd, int* argp);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 setsockopt(fd_handle s, int32 level, int32 optname, void* optval, int32 optlen);

    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 getsockopt(int sockfd, int level, int optname, void* optval, int32* optlen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 select(int32 nfds, fd_set* readFDS, fd_set* writeFDS, fd_set* exceptFDS, TimeVal* timeVal);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 recv(fd_handle s, void* ptr, int32 len, int32 flags);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 recvfrom(fd_handle s, void* ptr, int32 len, int32 flags, SockAddr* from, int32* fromLen);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 send(fd_handle s, void* ptr, int32 len, int32 flags);
    
    [CLink, CallingConvention(.Stdcall)]
    public extern static int32 sendto(fd_handle s, void* ptr, int32 len, int32 flags, SockAddr* to, int32 toLen);
    
    [CLink, CallingConvention(.Cdecl)]
    public extern static char8* strerror(int32 errnum);
    
    [CLink, CallingConvention(.Cdecl)]
    public extern static int32 shutdown(fd_handle sockfd, int how);

    [LinkName("UnixHelper_geterrno"), CallingConvention(.Cdecl)]
    public extern static int32 geterrno();

    [LinkName("UnixHelper_seterrno"), CallingConvention(.Cdecl)]
    public extern static void seterrno(int32 errnum);
}
#endif
