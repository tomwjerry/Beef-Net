using Beef_Net.Connection;
using System;

namespace Beef_Net
{
	public enum SocketState
	{
        Anything = 0x00,
		ServerSocket = 0x01,
		Blocking = 0x02,
		ReuseAddress = 0x04,
		CanSend = 0x08,
		CanReceive = 0x10,
		SSLActive = 0x20,
		NoDelay = 0x40
	}

	public enum SocketConnectionStatus
	{
		None = 0x0,
		Connecting = 0x1,
		Connected = 0x2,
		Disconnecting = 0x4
	}

	public enum SocketOperation
	{
		case Send;
		case Receive;

		public StringView StringValue
		{
			[NoDiscard]
			get
			{
				switch (this)
				{
				case .Send:    return "Send";
				case .Receive: return "Get";
				}
			}
		}
		public StringView SSLStringValue
		{
			[NoDiscard]
			get
			{
				switch (this)
				{
				case .Send:    return "SSLWrite";
				case .Receive: return "SSLRead";
				}
			}
		}
	}

    [CRepr]
    public struct SockAddr
    {
    	public uint16 sa_family;  // address family
    	public uint8[26] sa_data; // up to 26 bytes of direct address
    }

    public struct SocketAddress
    {
    	public sa_family_t Family;
    	public USockAddr u;

    	[Union]
    	public struct USockAddr
    	{
    		public sockaddr_in IPv4;
    		public sockaddr_in6 IPv6;
    	}
    }

    [CRepr]
    public struct fd_set
    {
    	public uint fd_count;             // how many are SET?
#if BF_PLATFORM_WINDOWS
    	public uint[FD_SETSIZE] fd_array; // an array of SOCKETs
#endif
    }

	/// Callback Event procedure for errors
	public delegate void SocketErrorEvent(StringView aMsg, Socket aSocket);
	/// Callback Event procedure for others
	public delegate void SocketEvent(Socket aSocket);
	/// Callback Event procedure for progress reports
	public delegate void SocketProgressEvent(Socket aSocket, int aBytes);

	[AlwaysInclude(IncludeAllMethods=true), Reflect(.All)]
	public class Socket : Handle
	{
		protected SocketAddress _address;
		protected SocketAddress _peerAddress;
		protected bool _reuseAddress;
		protected SocketConnectionStatus _connectionStatus;
		protected Socket _nextSock;
		protected Socket _prevSock;
		protected SocketState _socketState;
		protected SocketEvent _onFree;
		protected bool _blocking;
		protected int32 _listenBacklog;
		protected int32 _protocol;
		protected int32 _socketType;
		protected int32 _socketNet;
		protected Component _creator;
		protected Session _session;
		protected BaseConnection _connection;
    
    	protected int32 SocketType // inherit and publicize if you need to set this outside
		{
			get { return _socketType; }
			set { _socketType = value; }
		}
		public bool Connected { get { return _connectionStatus == .Connected; } }
		public bool Connecting { get { return _connectionStatus == .Connecting; } }
		public SocketConnectionStatus ConnectionStatus { get { return _connectionStatus; } }
		public int32 ListenBacklog
		{
			get { return _listenBacklog; }
			set { _listenBacklog = value; }
		}
		public int32 Protocol
		{
			get { return _protocol; }
			set { _protocol = value; }
		}
		public int32 SocketNet
		{
			get { return _socketNet; }
			set { _socketNet = value; }
		}
		public uint16 PeerPort
		{
			get {
				return _socketType == SOCK_STREAM
					? Common.ntohs(_address.u.IPv4.sin_port)
					: Common.ntohs(_peerAddress.u.IPv4.sin_port);
			}
		}
		public uint16 LocalPort { get { return Common.ntohs(_address.u.IPv4.sin_port); } }
		public ref Socket NextSock
		{
			get { return ref _nextSock; }
			set { _nextSock = value; }
		}
		public ref Socket PrevSock
		{
			get { return ref _prevSock; }
			set { _prevSock = value; }
		}
		public SocketState SocketState { get { return _socketState; } }
		public ref Component Creator { get { return ref _creator; } }
		public ref Session Session { get { return ref _session; } }
		
		protected SockAddr* GetIPAddressPointer()
		{
			switch (_socketNet)
			{
			case AF_INET:  return (SockAddr*)&_address.u.IPv4;
			case AF_INET6: return (SockAddr*)&_address.u.IPv6;
			default:       Runtime.FatalError("Unknown socket network type (not IPv4 or IPv6)");
			}
		}

		protected int32 GetIPAddressLength()
		{
			switch (_socketNet)
			{
			case AF_INET:  return sizeof(sockaddr_in);
			case AF_INET6: return sizeof(sockaddr_in6);
			default:       Runtime.FatalError("Unknown socket network type (not IPv4 or IPv6)");
			}
		}
		
		protected virtual bool SetupSocket(uint16 aPort, StringView aAddress)
		{
			bool done = false;

			if (_connectionStatus == .None)
			{
				int32 arg;
				done = true;
				_handle = Socket(_socketNet, _socketType, _protocol);

				if (_handle == INVALID_SOCKET)
					return Bail("Socket error", SocketError());

				SetOptions();

				if (_socketType == SOCK_DGRAM)
				{
					arg = 1;

					if (SetSockOpt(_handle, SOL_SOCKET, SO_BROADCAST, &arg, sizeof(int32)) == SOCKET_ERROR)
						return Bail("SetSockOpt error", SocketError());
				}

				if (_reuseAddress)
				{
					arg = 1;
					int32 opt = SO_REUSEADDR;

#if BF_PLATFORM_WINDOWS
					if (Environment.OSVersion.Platform == .Win32NT && Environment.OSVersion.Version.Major >= 5)
						opt = (int32)(~opt);
#endif

					if (SetSockOpt(_handle, SOL_SOCKET, opt, &arg, sizeof(int32)) == SOCKET_ERROR)
						return Bail("SetSockOpt error", SocketError());
				}

				// Darwin also needs `SO_NOSIGPIPE` to be set to 1

				Common.FillAddressInfo(ref _address, (uint16)_socketNet, aAddress, aPort);
				Common.FillAddressInfo(ref _peerAddress, (uint16)_socketNet, ADDR_BR, aPort);
			}

			return done;
		}

		protected virtual int32 DoSend(uint8* aData, int32 aSize)
		{
			if (_socketType == SOCK_STREAM)
			{
				return Send(_handle, aData, aSize, MSG);
			}
			else
			{
				int32 addrLen;

				switch (_address.u.IPv4.sin_family)
				{
				case AF_INET:
					{
						addrLen = sizeof(sockaddr_in);
						return SendTo(_handle, aData, aSize, MSG, (SockAddr*)&_peerAddress.u.IPv4, addrLen);
					}
				case AF_INET6:
					{
						addrLen = sizeof(sockaddr_in6);
						return SendTo(_handle, aData, aSize, MSG, (SockAddr*)&_peerAddress.u.IPv6, addrLen);
					}
				}
			}

			return 0;
		}

		protected virtual int32 DoRecv(uint8* aData, int32 aSize)
		{
			if (_socketType == SOCK_STREAM)
			{
				return Recv(_handle, aData, aSize, MSG);
			}
			else
			{
				int32 addrLen;

				switch (_address.u.IPv4.sin_family)
				{
				case AF_INET:
					{
						addrLen = sizeof(sockaddr_in);
						return RecvFrom(_handle, aData, aSize, MSG, (SockAddr*)&_peerAddress.u.IPv4, &addrLen);
					}
				case AF_INET6:
					{
						addrLen = sizeof(sockaddr_in6);
						return RecvFrom(_handle, aData, aSize, MSG, (SockAddr*)&_peerAddress.u.IPv6, &addrLen);
					}
				}
			}

			return 0;
		}

		protected virtual int32 HandleResult(int32 aResult, SocketOperation aOp)
		{
			int32 result = aResult;
			int32 lastError;

			if (aResult == SOCKET_ERROR)
			{
				lastError = SocketError();
				String tmp = scope .(aOp.StringValue);
				tmp.Append(" error");

				if (IsBlockError(lastError))
				{
					switch(aOp)
					{
					case .Send:
						{
							_socketState &= ~.CanSend;
							IgnoreWrite = false;
						}
					case .Receive:
						{
							_socketState &= ~.CanReceive;
							IgnoreRead = false;
						}
					}
				}
				else if (IsNonFatalError(lastError))
				{
					LogError(tmp, lastError); // non-fatals don't cause disconnect
				}
				else if (aOp == .Send && IsPipeError(lastError))
				{
					LogError(tmp, lastError);
					HardDisconnect(true);
#if DEBUG
					System.Diagnostics.Debug.WriteLine("Warning - check if we need aOp == soSend in the IF, perhaps bad recv is possible?");
#endif
				}
				else
				{
					Bail(tmp, lastError);
				}

				return 0;
			}

			return result;
		}

		public void GetPeerAddress(String aOutStr)
		{
			aOutStr.Clear();
			Common.NetAddrToStr(
				_socketType == SOCK_STREAM
					? _address.u.IPv4.sin_addr
					: _peerAddress.u.IPv4.sin_addr,
				aOutStr
			);
		}

		public void GetLocalAddress(String aOutStr)
		{
			aOutStr.Clear();
			sockaddr_in a = .();
			int32 l = sizeof(sockaddr_in);

			if (GetSockName(_handle, (SockAddr*)&a, &l) > 0)
				Common.NetAddrToStr(a.sin_addr, aOutStr);
		}

		[Inline]
		protected bool SendPossible()
		{
			if (_connectionStatus != .Connected)
				return LogError("Unable to send when not connected", -1);

			if (!_socketState.HasFlag(.CanSend))
			{
				if (_connection == null || _connection.[Friend]_onCanSend == null)
					return LogError("Send buffer full, try again later", -1);

				return false;
			}

			if (_socketState.HasFlag(.ServerSocket))
				return LogError("Unable to send on server a socket", -1);

			return true;
		}

		[Inline]
		protected bool ReceivePossible() =>
			(SocketConnectionStatus.Connected | SocketConnectionStatus.Disconnecting).HasFlag(_connectionStatus) &&
			_socketState.HasFlag(.CanReceive) && !_socketState.HasFlag(.ServerSocket);

		protected virtual void SetOptions()
		{
			SetBlocking(_blocking);
		}

		protected void SetBlocking(bool aValue)
		{
			if (_handle != INVALID_SOCKET) // we already have a socket
			{
				if (!SetBlocking(_handle, aValue))
				{
					Bail("Error on SetNoDelay", SocketError());
				}
				else
				{
					_blocking = true;

					if (aValue)
						_socketState |= .Blocking;
					else
						_socketState &= ~.Blocking;
				}
			}
		}

		protected void SetReuseAddress(bool aValue)
		{
			if (_connectionStatus == .None)
			{
				_reuseAddress = true;

				if (aValue)
					_socketState |= .ReuseAddress;
				else
					_socketState &= ~.ReuseAddress;
			}
		}

		protected void SetNoDelay(bool aValue)
		{
			if (_handle != INVALID_SOCKET) // we already have a socket
			{
				if (!SetNoDelay(_handle, aValue))
				{
					Bail("Error on SetNoDelay", SocketError());
				}
				else
				{
					if (aValue)
						_socketState |= .NoDelay;
					else
						_socketState &= ~.NoDelay;
				}
			}
		}

		protected void HardDisconnect(bool aIndNoShutdown = false)
		{
			bool needShut = _connectionStatus == .Connected && _socketType == SOCK_STREAM && !_socketState.HasFlag(.ServerSocket);

			if (aIndNoShutdown)
				needShut = false;

			_dispose = true;
			_socketState |= .CanSend;
			_socketState |= .CanReceive;
			_ignoreWrite = true;

			if ((SocketConnectionStatus.Connected | SocketConnectionStatus.Connecting | SocketConnectionStatus.Disconnecting).HasFlag(_connectionStatus))
			{
				_connectionStatus = .None;

				if (needShut && Shutdown(_handle, SHUT_RDWR) != 0)
					LogError("Shutdown error", SocketError());

				if (_eventer != null)
					_eventer.UnregisterHandle(this);

				if (CloseSocket(_handle) != 0)
					LogError("Closesocket error", SocketError());

				_handle = INVALID_SOCKET;
			}
		}

		protected void SoftDisconnect()
		{
			if ((SocketConnectionStatus.Connected | SocketConnectionStatus.Connecting).HasFlag(_connectionStatus))
			{
				if (_connectionStatus == .Connected && _socketType == SOCK_STREAM && !_socketState.HasFlag(.ServerSocket))
				{
					_connectionStatus = .Disconnecting;

					if (Shutdown(_handle, SHUT_WR) != 0)
						LogError("Shutdown error", SocketError());
				}
				else
				{
					HardDisconnect(); // UDP or ServerSocket
				}
			}
		}

		protected bool Bail(StringView aMsg, int32 aErrNum)
		{
			if (!_dispose)
			{
				Disconnect(true);
				LogError(aMsg, aErrNum);
			}

			return false;
		}

		protected virtual bool LogError(StringView aMsg, int32 aErrNum)
		{
			if (_onError != null)
			{
				String tmp = scope .(aMsg);

				if (aErrNum > 0)
					StrError(aErrNum, tmp);

				_onError(this, tmp);
			}

			return false;
		}

		public this() : base()
		{
			_handle = INVALID_SOCKET;
			_listenBacklog = DEFAULT_BACKLOG;
			_prevSock = null;
			_nextSock = null;
			_socketState = .CanSend;
			_connectionStatus = .None;
			_socketType = SOCK_STREAM;
			_socketNet = AF_INET;
			_protocol = PROTO_TCP;
		}

		public ~this()
		{
			if (_onFree != null)
				_onFree(this);

			if (_eventer != null)
				_eventer.[Friend]InternalUnplugHandle(this);

			Disconnect(true);
		}

		public virtual bool SetState(SocketState aState, bool aIndTurnOn = true)
		{
			switch (aState)
			{
			case .ServerSocket:
				{
					if (aIndTurnOn)
						_socketState |= aState;
					else
						Runtime.FatalError("Can not turn off server socket feature");
				}
			case .Blocking:     SetBlocking(aIndTurnOn);
			case .ReuseAddress: SetReuseAddress(aIndTurnOn);
			case .CanSend,
				 .CanReceive: 
				{
					if (aIndTurnOn)
						_socketState |= aState;
					else
						_socketState &= ~aState;
				}
			case .SSLActive:    Runtime.FatalError("Can not turn SSL/TLS on in TLSocket instance");
			case .NoDelay:      SetNoDelay(aIndTurnOn);
            default: break;
			}

			return true;
		}

		public bool Listen(uint16 aPort, StringView aIntf = ADDR_ANY)
		{
			bool result = false;

			if (_connectionStatus != .None)
				Disconnect(true);

			SetupSocket(aPort, aIntf);

			if (Bind(_handle, GetIPAddressPointer(), GetIPAddressLength()) == SOCKET_ERROR)
				Bail("Error on bind", SocketError());
			else
				result = true;

			if (_socketType == SOCK_STREAM && result)
				if (Listen(_handle, _listenBacklog) == SOCKET_ERROR)
					result = Bail("Error on Listen", SocketError());

			return result;
		}

		public bool Accept(fd_handle aSerSock)
		{
			int32 addrLen = GetIPAddressLength();

			if (_connectionStatus != .None)
				Disconnect(true);

			_handle = Accept(aSerSock, GetIPAddressPointer(), &addrLen);

			if (_handle != INVALID_SOCKET)
			{
				SetOptions();
				_isAcceptor = true;
				return true;
			}
			else
			{
				Bail("Error on accept", SocketError());
			}

			return false;
		}

		public bool Connect(StringView aAddress, uint16 aPort)
		{
			if (_connectionStatus != .None)
				Disconnect(true);

			if (SetupSocket(aPort, aAddress))
			{
				Connect(_handle, GetIPAddressPointer(), GetIPAddressLength());

				_connectionStatus = .Connecting;
				return true;
			}

			return false;
		}

		public virtual int32 Send(uint8* aData, int32 aSize)
		{
			int32 result = 0;
			Runtime.Assert(aSize != 0);

			if (SendPossible())
			{
				if (aSize <= 0)
				{
					LogError("Send error: Size <= 0", -1);
					return 0;
				}

				return HandleResult(DoSend(aData, aSize), .Send);
			}

			return result;
		}

		public int32 SendMessage(StringView aMsg) =>
			Send((uint8*)aMsg.Ptr, (int32)aMsg.Length);

		public virtual int32 Get(uint8* aData, int32 aSize)
		{
			int32 result = 0;
			Runtime.Assert(aSize > 0);

			if (ReceivePossible())
			{
				result = DoRecv(aData, aSize);

				if (result == 0)
				{
					if (_socketType == SOCK_STREAM)
					{
						Disconnect();
					}
					else
					{
						Bail("Receive Error [0 on recvfrom with UDP]", 0);
						return 0;
					}
				}

				return HandleResult(result, .Receive);
			}

			return result;
		}

		public int32 GetMessage(String aOutStr)
		{
			aOutStr.Clear();
			uint8* tmpPtr = scope .[BUFFER_SIZE]*;
			int32 len = Get(tmpPtr, BUFFER_SIZE);
			aOutStr.Append((char8*)tmpPtr, len);
			return (int32)aOutStr.Length;
		}

		public virtual void Disconnect(bool aIndForced = false)
		{
			// don't do anything when already invalid
			if (_dispose && _handle == INVALID_SOCKET && _connectionStatus == .None)
				return;

			if (aIndForced)
				HardDisconnect();
			else
				SoftDisconnect();
		}

        public static bool SetNoDelay(fd_handle aHandle, bool aValue)
        {
        	uint32 opt = aValue ? 1 : 0;
        	
        	if (SetSockOpt(aHandle, PROTO_TCP, TCP_NODELAY, &opt, sizeof(int)) < 0)
        		return false;

        	return true;
        }

        public static bool SetBlocking(fd_handle aHandle, bool aValue)
        {
        	uint32 opt = aValue ? 1 : 0;
        	
        	if (IOCtlSocket(aHandle, (int32)FIONBIO, &opt) == SOCKET_ERROR)
        		return false;

        	return true;
        }

        public static bool IsBlockError(int32 aErrorNum) =>
#if BF_PLATFORM_WINDOWS
        	aErrorNum == WSAEWOULDBLOCK;
#else
            aErrorNum == EWOULDBLOCK;
#endif

        public static bool IsNonFatalError(int32 aErrorNum) =>
#if BF_PLATFORM_WINDOWS
        	(aErrorNum == WSAEINVAL)        || (aErrorNum == WSAEFAULT)       ||
        	(aErrorNum == WSAEOPNOTSUPP)    || (aErrorNum == WSAEMSGSIZE)     ||
        	(aErrorNum == WSAEADDRNOTAVAIL) || (aErrorNum == WSAEAFNOSUPPORT) ||
        	(aErrorNum == WSAEDESTADDRREQ);
#else
            (aErrorNum == EINVAL)        || (aErrorNum == EFAULT)       ||
            (aErrorNum == EOPNOTSUPP)    || (aErrorNum == EMSGSIZE)     ||
            (aErrorNum == EADDRNOTAVAIL) || (aErrorNum == EAFNOSUPPORT) ||
            (aErrorNum == EDESTADDRREQ);
#endif

        public static bool IsPipeError(int32 aErrorNum)
        {
#if BF_PLATFORM_WINDOWS
        	bool result = aErrorNum == WSAECONNRESET;
#else
            bool result = aErrorNum == ECONNRESET;
#endif
        	return result;
        }

        public static int32 SocketError() =>
#if BF_PLATFORM_WINDOWS
        	(int32)WinSock2.WSAGetLastError();
#else
            UnixSock.geterrno();
#endif

        public static void StrError(int32 aErrNum, String aOutStr, bool aIndUseUTF8 = false)
        {
            aOutStr.AppendF(" [{0}]: ", aErrNum);
            String tmp = scope .();
#if BF_PLATFORM_WINDOWS
        	uint32 MAX_ERROR = 1024;

        	if (aIndUseUTF8)
        	{
        		char16* tmpPtr = scope char16[MAX_ERROR]*;
        		WinSock2.FormatMessageW(Common.FORMAT_MESSAGE_FROM_SYSTEM | Common.FORMAT_MESSAGE_IGNORE_INSERTS | Common.FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    null, (uint32)aErrNum, 0, &tmpPtr[0], MAX_ERROR, null);
        		System.Text.UTF16.Decode(tmpPtr, tmp);
        	}
        	else
        	{
        		char8* tmpPtr = scope char8[MAX_ERROR]*;
        		int len = (int)WinSock2.FormatMessageA(Common.FORMAT_MESSAGE_FROM_SYSTEM | Common.FORMAT_MESSAGE_IGNORE_INSERTS | Common.FORMAT_MESSAGE_ARGUMENT_ARRAY,
                    null, (uint32)aErrNum, 0, &tmpPtr[0], MAX_ERROR, null);
        		tmp.Append(tmpPtr, len);
        	}

        	aOutStr.Append(tmp);
#elif BF_PLATFORM_LINUX
        	aOutStr.Append(Socket.StrError(aErrNum, tmp));
#endif
        }

        public static fd_handle Accept(fd_handle aHandle, SockAddr* aAddr, int32* aAddrLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.accept(aHandle, (sockaddr_in*)aAddr, aAddrLen);
#else
            UnixSock.accept(aHandle, aAddr, aAddrLen);
#endif

        public static int32 Bind(fd_handle aHandle, SockAddr* aName, int32 aNameLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.bind(aHandle, (sockaddr_in*)aName, aNameLen);
#else
            UnixSock.bind(aHandle, aName, aNameLen);
#endif

        public static int32 CloseSocket(fd_handle aHandle) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.closesocket(aHandle);
#else
            UnixSock.close(aHandle);
#endif

        public static int32 Connect(fd_handle aHandle, SockAddr* aName, int32 aNameLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.connect(aHandle, (sockaddr_in*)aName, aNameLen);
#else
            UnixSock.connect(aHandle, aName, aNameLen);
#endif

        public static int32 IOCtlSocket(fd_handle aHandle, int32 cmd, uint32* aArgP) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.ioctlsocket(aHandle, cmd, aArgP);
#else
            UnixSock.ioctl(aHandle, cmd, (int*)aArgP);
#endif

        public static int32 GetPeerName(fd_handle aHandle, SockAddr* aName, int32* aNameLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.getpeername(aHandle, (sockaddr_in*)aName, aNameLen);
#else
            UnixSock.getpeername(aHandle, aName, aNameLen);
#endif

        public static int32 GetSockName(fd_handle aHandle, SockAddr* aName, int32* aNameLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.getsockname(aHandle, (sockaddr_in*)aName, aNameLen);
#else
            UnixSock.getsockname(aHandle, aName, aNameLen);
#endif

        public static int32 SetSockOpt(fd_handle aHandle, int32 aLevel, int32 aOptName, void* aOptVal, int32 aOptLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.setsockopt(aHandle, aLevel, aOptName, aOptVal, aOptLen);
#else
            UnixSock.setsockopt(aHandle, aLevel, aOptName, aOptVal, aOptLen);
#endif
            
        public static int32 GetSockOpt(fd_handle aHandle, int32 aLevel, int32 aOptName, void* aOptVal, int32* aOptLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.getsockopt(aHandle, aLevel, aOptName, aOptVal, aOptLen);
#else
            UnixSock.getsockopt(aHandle, aLevel, aOptName, aOptVal, aOptLen);
#endif

        public static int32 Listen(fd_handle aHandle, int32 aBacklog) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.listen(aHandle, aBacklog);
#else
            UnixSock.listen(aHandle, aBacklog);
#endif

        public static int32 Recv(fd_handle aHandle, uint8* aBuf, int32 aLen, int32 aFlags) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.recv(aHandle, aBuf, aLen, aFlags);
#else
            UnixSock.recv(aHandle, aBuf, aLen, aFlags);
#endif

        public static int32 RecvFrom(fd_handle aHandle, uint8* aBuf, int32 aLen, int32 aFlags, SockAddr* aFromAddr, int32* aFromLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.recvfrom(aHandle, aBuf, aLen, aFlags, (sockaddr_in*)aFromAddr, aFromLen);
#else
            UnixSock.recvfrom(aHandle, aBuf, aLen, aFlags, aFromAddr, aFromLen);
#endif

        public static int32 Select(int nfds, fd_set* aReadFds, fd_set* aWriteFds, fd_set* aExceptFds, TimeVal* timeout) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.select(nfds, aReadFds, aWriteFds, aExceptFds, timeout);
#else
            UnixSock.select((int32)nfds, aReadFds, aWriteFds, aExceptFds, timeout);
#endif

        public static int32 Send(fd_handle aHandle, uint8* aBuf, int32 aLen, int32 aFlags) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.send(aHandle, aBuf, aLen, aFlags);
#else
            UnixSock.send(aHandle, aBuf, aLen, aFlags);
#endif

        public static int32 SendTo(fd_handle aHandle, uint8* aBuf, int32 aLen, int32 aFlags, SockAddr* aToAddr, int32 aToLen) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.sendto(aHandle, aBuf, aLen, aFlags, (sockaddr_in*)aToAddr, aToLen);
#else
            UnixSock.sendto(aHandle, aBuf, aLen, aFlags, aToAddr, aToLen);
#endif

        public static int32 Shutdown(fd_handle aHandle, int32 aHow) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.shutdown(aHandle, aHow);
#else
            UnixSock.shutdown(aHandle, aHow);
#endif

        public static fd_handle Socket(int32 aAf, int32 aType, int32 aProtocol) =>
#if BF_PLATFORM_WINDOWS
        	WinSock2.socket(aAf, aType, aProtocol);
#else
            UnixSock.shutdown(aAf, aType);
#endif
	}
}
