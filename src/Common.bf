using System;
using System.Collections;
using System.Globalization;

namespace Beef_Net
{
	static class Common
	{
		public const uint32 FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x100U;
		public const uint32 FORMAT_MESSAGE_IGNORE_INSERTS  = 0x200U;
		public const uint32 FORMAT_MESSAGE_FROM_STRING     = 0x400U;
		public const uint32 FORMAT_MESSAGE_FROM_HMODULE    = 0x800U;
		public const uint32 FORMAT_MESSAGE_FROM_SYSTEM     = 0x1000U;
		public const uint32 FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x2000U;
		public const uint32 FORMAT_MESSAGE_MAX_WIDTH_MASK  = 255;

		[Inline]
		public static uint16 bswap_16(uint16 val) =>
			((val >> 8) & 0xFFU) |
			((val & 0xFFU) << 8);

		[Inline]
		public static uint32 bswap_32(uint32 val) =>
			((val & 0xFF000000U) >> 24) |
			((val & 0x00FF0000U) >>  8) |
			((val & 0x0000FF00U) <<  8) |
			((val & 0x000000FFU) << 24);

		[Inline]
		public static uint64 bswap_64(uint64 val) =>
			((val & 0xFF00000000000000UL) >> 56) |
			((val & 0x00FF000000000000UL) >> 40) |
			((val & 0x0000FF0000000000UL) >> 24) |
			((val & 0x000000FF00000000UL) >>  8) |
			((val & 0x00000000FF000000UL) <<  8) |
			((val & 0x0000000000FF0000UL) << 24) |
			((val & 0x000000000000FF00UL) << 40) |
			((val & 0x00000000000000FFUL) << 56);

#if BF_LITTLE_ENDIAN
		public static uint16 htons(uint16 val) =>
			bswap_16(val);

		public static uint32 htonl(uint32 val) =>
			bswap_32(val);

		public static uint16 ntohs(uint16 val) =>
			bswap_16(val);

		public static uint32 ntohl(uint32 val) =>
			bswap_32(val);
#else
		public static uint16 htons(uint16 val) => val;

		public static uint32 htonl(uint32 val) => val;

		public static uint16 ntohs(uint16 val) => val;

		public static uint32 ntohl(uint32 val) => val;
#endif

		public static void GetHostIP(StringView aName, String aOutStr)
		{
			aOutStr.Clear();
#if BF_PLATFORM_WINDOWS
			HostEnt* he = null;
			he = WinSock2.gethostbyname(aName.Ptr);

			if (he != null)
				NetAddrToStr(*(in_addr*)he.h_addr_list[0], aOutStr);
#endif
		}

		public static void NetAddrToStr(in_addr aEntry, String aOutStr)
		{
			aOutStr.Clear();
			aOutStr.AppendF("{0}.{1}.{2}.{3}", aEntry.s_bytes[0], aEntry.s_bytes[1], aEntry.s_bytes[2], aEntry.s_bytes[3]);
		}

		public static void HostAddrToStr(in_addr aEntry, String aOutStr) =>
			NetAddrToStr(in_addr() { s_addr = htonl(aEntry.s_addr) }, aOutStr);

		public static in_addr StrToHostAddr(StringView aIP)
		{
			in_addr result = .() { s_addr = 0 };
			String tmp = scope .(aIP);
			String dummy = scope .();
			int j;

			for (int i = 0; i < 4; i++)
			{
				if (i < 3)
				{
					j = tmp.IndexOf('.');

					if (j == 0)
						return result;

					dummy.Set(tmp.Substring(0, j));
					tmp.Remove(0, j + 1);
				}
				else
				{
					dummy.Set(tmp);
				}

				if (UInt32.Parse(dummy) case .Ok(let val))
					result.s_bytes[i] = (uint8)val;
				else
					return result;
			}

			result.s_addr = ntohl(result.s_addr);
			return result;
		}

		public static in_addr StrToNetAddr(StringView aIP) =>
			.() { s_addr = htonl(StrToHostAddr(aIP).s_addr) };

		public static void HostAddrToStr6(in6_addr aEntry, String aOutStr)
		{
			var aOutStr;

			if (aOutStr == null)
				aOutStr = new .();

			List<uint8> zr1 = new .();
			List<uint8> zr2 = new .();
			uint8 zc1 = 0;
			uint8 zc2 = 0;

			for (uint8 i = 0; i <= 7; i++)
			{
				if (aEntry.u6_addr16[i] == 0)
				{
					zr2.Add(i);
					zc2++;
				}
				else
				{
					if (zc1 < zc2)
					{
						zc1 = zc2;
						delete zr1;
						zr1 = zr2;
						zc2 = 0;
						zr2 = new .();
					}
				}
			}

			if (zc1 < zc2)
			{
				zc1 = zc2;
				zr1 = zr2;
			}

			aOutStr.Clear();
			bool have_skipped = false;
			String tmp = scope .();

			for (uint8 i = 0; i <= 7; i++)
			{
				if (!zr1.Contains(i))
				{
					if (have_skipped)
					{
						if (aOutStr.IsEmpty)
							aOutStr.Set("::");
						else
							aOutStr.Append(':');

						have_skipped = false;
					}

					tmp.Clear();
					ntohs(aEntry.u6_addr16[i]).ToString(tmp, "X", CultureInfo.InvariantCulture);
					aOutStr.AppendF("{0}:", tmp);
				}
				else
				{
					have_skipped = true;
				}
			}

			if (have_skipped)
			{
				if (aOutStr.IsEmpty)
					aOutStr.Set("::");
				else
					aOutStr.Append(':');
			}
			
			if (aOutStr.IsEmpty)
				aOutStr.Set("::");

			if (!zr1.Contains(7))
				aOutStr.RemoveFromEnd(1);
			
			delete zr1;
			delete zr2;
		}

		public static in6_addr StrToHostAddr6(StringView aIP)
		{
			String tmpIp = scope .(aIP);
			in6_addr result = .();
			Internal.MemSet(&result, 0, sizeof(in6_addr));

			// Every 16-bit block is converted at its own and stored into Result. When the '::' zero-spacer is found, its location is stored. Afterwards the
			// address is shifted and zero-filled.
			int index = 0;
			int zeroAt = -1;
			int p = tmpIp.IndexOf(':');
			uint16 w = 0;
			bool failed = false;
			String part = scope .();

			while (p > 0 && tmpIp.Length > 0 && index < 8)
			{
				part.Set("0x");
				part.Append(tmpIp.Substring(0, p - 1));
				tmpIp.Remove(0, p);

				if (part.Length > 0) // is there a digit?
				{
					if (Int32.Parse(part, .HexNumber) case .Ok(let val))
						w = (uint16)val;
					else
						failed = true;
				}
				else
				{
					w = 0;
				}

				result.u6_addr16[index] = htons(w);

				if (failed)
				{	
					Internal.MemSet(&result, 0, sizeof(in6_addr));
					return result;
				}

				if (tmpIp[1] == ':')
				{
					zeroAt = index;
					tmpIp.Remove(0);
				}

				index++;
				p = tmpIp.IndexOf(':');

				if (p == 0)
					p = tmpIp.Length + 1;
			}

			// address      a:b:c::f:g:h
			// Result now   a : b : c : f : g : h : 0 : 0, ZeroAt = 2, Index = 6
			// Result after a : b : c : 0 : 0 : f : g : h
			if (zeroAt >= 0)
			{
				Internal.MemMove(&result.u6_addr16[zeroAt + 1], &result.u6_addr16[(8 - index) + zeroAt + 1], 2 * (index - zeroAt - 1));
				Internal.MemSet(&result.u6_addr16[zeroAt + 1], 0, 2 * (8 - index));
			}
			
			return result;
		}

		public static void NetAddrToStr6(in6_addr aEntry, String aOutStr) =>
			HostAddrToStr6(aEntry, aOutStr);

		public static in6_addr StrToNetAddr6(StringView aIP) =>
			StrToHostAddr6(aIP);

		[Inline]
		public static bool IsIP6Empty(sockaddr_in6 aIP6)
		{
			for (int i = 0; i <= aIP6.sin6_addr.u6_addr32.Count; i++) do
				if (aIP6.sin6_addr.u6_addr32[i] != 0)
					return false;
			
			return true;
		}

		public static void GetHostIP6(StringView aName, String aOutStr)
		{
			aOutStr.Clear();
			AddrInfo h = .();
			AddrInfo* r;

			Internal.MemSet(&h, 0, sizeof(AddrInfo));
			h.ai_family = AF_INET6;
			h.ai_protocol = PF_INET6;
			h.ai_socktype = SOCK_STREAM;

#if BF_PLATFORM_WINDOWS
			int n = WinSock2.getaddrinfo(aName.Ptr, null, &h, out r);
#else
            r = scope AddrInfo();
            int n = UnixSock.getaddrinfo(aName.Ptr, null, &h, &r);
#endif
			
			if (n != 0)
				return;

			NetAddrToStr6(.(*r.ai_addr), aOutStr);
#if BF_PLATFORM_WINDOWS
			WinSock2.freeaddrinfo(r);
#endif
		}

		public static void FillAddressInfo(ref SocketAddress aAddrInfo, sa_family_t aFamily, StringView aAddress, uint16 aPort)
		{
			aAddrInfo.u.IPv4.sin_family = aFamily;
			aAddrInfo.u.IPv4.sin_port = htons(aPort);

			switch (aFamily)
			{
			case AF_INET:
				{
					aAddrInfo.u.IPv4.sin_addr.s_addr = StrToNetAddr(aAddress).s_addr;

					if (aAddress != ADDR_ANY && aAddrInfo.u.IPv4.sin_addr.s_addr == 0)
					{
						String tmp = scope .();
						GetHostIP(aAddress, tmp);
						aAddrInfo.u.IPv4.sin_addr.s_addr = StrToNetAddr(tmp).s_addr;
					}
				}
			case AF_INET6:
				{
					
					aAddrInfo.u.IPv6.sin6_addr = StrToNetAddr6(aAddress);

					if (aAddress != ADDR6_ANY && IsIP6Empty(aAddrInfo.u.IPv6))
					{
						String tmp = scope .();
						GetHostIP6(aAddress, tmp);
						aAddrInfo.u.IPv6.sin6_addr = StrToNetAddr6(tmp);
					}
				}
			}
		}

		/*
		https://github.com/alrieckert/freepascal/blob/master/packages/rtl-extra/src/inc/sockets.inc
		https://github.com/farshadmohajeri/extpascal/blob/master/SocketsDelphi.pas
		https://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
		*/
	}
}
