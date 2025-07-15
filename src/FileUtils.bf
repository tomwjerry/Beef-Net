using System;
using System.IO;

namespace Beef_Net
{
	[CRepr]
	public struct SearchRec
	{
		public int64 Time;
		public int64 Size;
		public Platform.BfpFileAttributes Attr;
		public String Name;
		public Platform.BfpFileAttributes ExcludeAttr;
		public FileEnumerator FileFinder;

		public DateTime TimeStamp { get { return DateTime.FromFileTime(Time); } }
	}

	public class FileUtils
	{
		public static int32 FindMatch(ref SearchRec aF, String aName)
		{
			// Find file with correct attribute
			while (aF.FileFinder.Current.GetFileAttributes() & aF.ExcludeAttr != 0)
				if (!aF.FileFinder.MoveNext())
					return -1; // TODO: Whats our error?

			// Convert some attributes back
			aF.Time = (int64)aF.FileFinder.Current.GetLastWriteTime().ToFileTime();
			aF.Size = aF.FileFinder.Current.GetFileSize();
			aF.Attr = aF.FileFinder.Current.GetFileAttributes();
            aF.FileFinder.Current.GetFileName(aName);
			return 0;
		}

		public static void InternalFindClose(FileEnumerator fe)
		{
		   	fe.Dispose();
		}

		public static int32 InternalFindFirst(StringView aPath, Platform.BfpFileAttributes aAttr, ref SearchRec aRslt, String aName)
		{
			aName.Set(aPath);
			aRslt.Attr = aAttr;
			// $1e = faHidden or faSysFile or faVolumeID (appears to be deprecated so not used here) or faDirectory
			aRslt.ExcludeAttr = (~aAttr) & .Hidden | .System | .Directory;

			// FindFirstFile is a Win32 Call
			aRslt.FileFinder = Directory.EnumerateFiles(aPath);

			// TODO: Check if FileFinder is invalid or something

			// Find file with correct attribute
			int32 result = FindMatch(ref aRslt, aName);

			if (result != 0)
				InternalFindClose(aRslt.FileFinder);

			return result;
		}

		public static int32 InternalFindNext(ref SearchRec aRslt, String aName) =>
            aRslt.FileFinder.MoveNext() ? 0 : -1; // TODO: Get error

		public static int FindFirst(StringView aPath, Platform.BfpFileAttributes aAttr, ref SearchRec aRslt)
		{
			int result = InternalFindFirst(aPath, aAttr, ref aRslt, aRslt.Name);
			/*
		  	if (result == 0)
		    	SetCodePage(Rslt.Name, DefaultRTLFileSystemCodePage);
			*/
			return result;
		}

		public static int FindNext(ref SearchRec aRslt)
		{
			int result = InternalFindNext(ref aRslt, aRslt.Name);

			/*
		  	if (result == 0)
		    	SetCodePage(Rslt.Name, DefaultRTLFileSystemCodePage);
			*/
			return result;
		}

		public static void FindClose(ref SearchRec aF) =>
			InternalFindClose(aF.FileFinder);
	}
}
