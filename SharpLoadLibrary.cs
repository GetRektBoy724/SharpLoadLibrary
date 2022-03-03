using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;
using System.Reflection;
using System.IO.MemoryMappedFiles;
using System.Threading;
using System.Security.Cryptography;

public class PEReader
{
    public struct IMAGE_DOS_HEADER
    {      // DOS .EXE header
        public UInt16 e_magic;              // Magic number
        public UInt16 e_cblp;               // Bytes on last page of file
        public UInt16 e_cp;                 // Pages in file
        public UInt16 e_crlc;               // Relocations
        public UInt16 e_cparhdr;            // Size of header in paragraphs
        public UInt16 e_minalloc;           // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
        public UInt16 e_ss;                 // Initial (relative) SS value
        public UInt16 e_sp;                 // Initial SP value
        public UInt16 e_csum;               // Checksum
        public UInt16 e_ip;                 // Initial IP value
        public UInt16 e_cs;                 // Initial (relative) CS value
        public UInt16 e_lfarlc;             // File address of relocation table
        public UInt16 e_ovno;               // Overlay number
        public UInt16 e_res_0;              // Reserved words
        public UInt16 e_res_1;              // Reserved words
        public UInt16 e_res_2;              // Reserved words
        public UInt16 e_res_3;              // Reserved words
        public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;            // OEM information; e_oemid specific
        public UInt16 e_res2_0;             // Reserved words
        public UInt16 e_res2_1;             // Reserved words
        public UInt16 e_res2_2;             // Reserved words
        public UInt16 e_res2_3;             // Reserved words
        public UInt16 e_res2_4;             // Reserved words
        public UInt16 e_res2_5;             // Reserved words
        public UInt16 e_res2_6;             // Reserved words
        public UInt16 e_res2_7;             // Reserved words
        public UInt16 e_res2_8;             // Reserved words
        public UInt16 e_res2_9;             // Reserved words
        public UInt32 e_lfanew;             // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { 
                int i = Name.Length - 1;
                while (Name[i] == 0) {
                    --i;
                }
                char[] NameCleaned = new char[i+1];
                Array.Copy(Name, NameCleaned, i+1);
                return new string(NameCleaned); 
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {

        Stub = 0x00000000,

    }


    /// The DOS header

    private IMAGE_DOS_HEADER dosHeader;

    /// The file header

    private IMAGE_FILE_HEADER fileHeader;

    /// Optional 32 bit file header 

    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

    /// Optional 64 bit file header 

    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    /// Image Section headers. Number of sections is in the file header.

    private IMAGE_SECTION_HEADER[] imageSectionHeaders;

    private byte[] rawbytes;



    public PEReader(string filePath)
    {
        // Read in the DLL or EXE and get the timestamp
        using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = System.IO.File.ReadAllBytes(filePath);

        }
    }

    public PEReader(byte[] fileBytes)
    {
        // Read in the DLL or EXE and get the timestamp
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }

            rawbytes = fileBytes;

        }
    }


    public static T FromBinaryReader<T>(BinaryReader reader)
    {
        // Read in a byte array
        byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

        // Pin the managed memory while, copy it out the data, then unpin it
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        handle.Free();

        return theStructure;
    }

    public bool Is32BitHeader
    {
        get
        {
            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
    }


    public IMAGE_FILE_HEADER FileHeader
    {
        get
        {
            return fileHeader;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
    {
        get
        {
            return optionalHeader32;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
    {
        get
        {
            return optionalHeader64;
        }
    }

    public IMAGE_SECTION_HEADER[] ImageSectionHeaders
    {
        get
        {
            return imageSectionHeaders;
        }
    }

    public byte[] RawBytes
    {
        get
        {
            return rawbytes;
        }

    }

}

public class SysGate {

    public bool IsGateReady = false;

    public bool IsSyscallReady = false;

    public IntPtr GatePositionAddress = IntPtr.Zero;

    public Dictionary<UInt64, SyscallTableEntry> SyscallTableEntries = new Dictionary<UInt64, SyscallTableEntry>();

    public struct SyscallTableEntry {
        public string Name;
        public UInt64 Hash;
        public Int64 ExportAddress;
        public Int16 SyscallID;
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static UInt32 JITMeDaddy() {
        return new UInt32();
    }

    public static UInt64 GetFunctionDJB2Hash(string FunctionName) {
        if (string.IsNullOrEmpty(FunctionName))
            return 0;

        UInt64 hash = 0x7734773477347734;
        foreach (char c in FunctionName)
            hash = ((hash << 0x5) + hash) + (byte)c;

        return hash;
    }

    public static unsafe void Copy(byte[] source, int startIndex, IntPtr destination, int length) {
        if (source == null || source.Length == 0 || destination == IntPtr.Zero || length == 0) {
            throw new ArgumentNullException("Exception : One or more of the arguments are zero/null!");
        }
        if ((startIndex + length) > source.Length) {
            throw new ArgumentOutOfRangeException("Exception : startIndex and length exceeds the size of source bytes!");
        }
        int targetIndex = 0;
        byte* TargetByte = (byte*)(destination.ToPointer());
        for (int sourceIndex = startIndex; sourceIndex < (startIndex + length); sourceIndex++) {
            *(TargetByte + targetIndex) = source[sourceIndex];
            targetIndex++;
        }
    }

    public bool Gate(UInt64 Hash) {
        if (!this.IsGateReady || GatePositionAddress == IntPtr.Zero) {
            bool result = this.PrepareGateSpace();
            if (!result) {
                Console.WriteLine("Failed to prepare gate space!");
                return false;
            }
        }

        if (!this.SyscallTableEntries.ContainsKey(Hash))
            return false;
        Int16 SyscallID = this.SyscallTableEntries[Hash].SyscallID;

        byte[] stub = new byte[24] { // a bit of obfuscation, i know it is an eyesore
            Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16),
            Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16),
            Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16),
            Convert.ToByte("75", 16), Convert.ToByte("03", 16),
            Convert.ToByte("0F", 16), Convert.ToByte("05", 16),
            Convert.ToByte("C3", 16),
            Convert.ToByte("CD", 16), Convert.ToByte("2E", 16),
            Convert.ToByte("C3", 16)
        };

        Copy(stub, 0, this.GatePositionAddress, stub.Length);
        Array.Clear(stub, 0, stub.Length); // clean up
        return true;
    }

    public bool PrepareGateSpace() {
        // Find and JIT the method to generate RWX space
        MethodInfo method = typeof(SysGate).GetMethod("JITMeDaddy", BindingFlags.Static | BindingFlags.NonPublic);
        if (method == null) {
            Console.WriteLine("Unable to find the method");
            return false;
        }
        RuntimeHelpers.PrepareMethod(method.MethodHandle);

        IntPtr pMethod = method.MethodHandle.GetFunctionPointer();

        this.GatePositionAddress = (IntPtr)pMethod; // this works fine
        this.IsGateReady = true;
        return true;
    }

    public void CollectSyscalls() {
        if (IsSyscallReady) {
            this.ResetEntries();
        }

        IntPtr ModuleBase = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            List<SyscallTableEntry> TempNtFunctionList = new List<SyscallTableEntry>();

            for (int i = 0; i < NumberOfNames; i++) {
                string CurrentFunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                Int32 CurrentFunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 CurrentFunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (CurrentFunctionOrdinal - OrdinalBase))));
                IntPtr CurrentFunctionPtr = (IntPtr)((Int64)ModuleBase + CurrentFunctionRVA);

                if (CurrentFunctionName.StartsWith("Nt") && !CurrentFunctionName.StartsWith("Ntdll")) {
                    SyscallTableEntry currententrytable = new SyscallTableEntry();
                    currententrytable.Name = CurrentFunctionName;
                    currententrytable.ExportAddress = (Int64)CurrentFunctionPtr;
                    currententrytable.Hash = GetFunctionDJB2Hash(CurrentFunctionName);
                    TempNtFunctionList.Add(currententrytable);
                }
            }

            TempNtFunctionList = TempNtFunctionList.OrderBy(o => o.ExportAddress).ToList(); // order by address
            TempNtFunctionList = TempNtFunctionList.GroupBy(x => x.ExportAddress).Select(x => x.First()).ToList(); // remove duplicate if exist

            for (short i = 0; i < TempNtFunctionList.Count; i++) {
                SyscallTableEntry currententrytable = new SyscallTableEntry();
                currententrytable.Name = TempNtFunctionList[i].Name;
                currententrytable.ExportAddress = TempNtFunctionList[i].ExportAddress;
                currententrytable.SyscallID = i; // assign the syscall IDs
                currententrytable.Hash = TempNtFunctionList[i].Hash;
                this.SyscallTableEntries.Add(TempNtFunctionList[i].Hash, currententrytable);
            }
            this.IsSyscallReady = true;
        }catch { }
    }

    public void ResetEntries() {
        this.SyscallTableEntries.Clear();
        this.IsSyscallReady = false;
    }
}

public class SharpLoadLibrary {

    [DllImport("kernel32.dll", SetLastError=true, CharSet = CharSet.Ansi)]
    static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

    [DllImport("kernel32.dll")]
    static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    [DllImport("kernel32.dll", EntryPoint = "RtlAddFunctionTable", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool RtlAddFunctionTable(IntPtr FunctionTable, UInt32 EntryCount, IntPtr BaseAddress);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTAVM(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 NTPVM(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void IMAGE_TLS_CALLBACK_Delegate(IntPtr DllHandle, Int32 Reason, IntPtr Reserved);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool DllMainDelegate(IntPtr DllHandle, Int32 Reason, IntPtr Reserved);

	public static UInt32 PAGE_READWRITE = 0x04; 
    public static UInt32 PAGE_EXECUTE_READ = 0x20;
    public static UInt32 PAGE_NOACCESS = 0x01;
    public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    public static UInt32 PAGE_READONLY = 0x02;
    public static UInt32 PAGE_EXECUTE = 0x10;

    public static uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    public static uint IMAGE_SCN_MEM_READ = 0x40000000;
    public static uint IMAGE_SCN_MEM_WRITE = 0x80000000;

    [Flags]
    public enum AllocationType : ulong
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    };

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }
        return FunctionPtr;
    }

	public static bool IsValidPE(byte[] filebytes) {
		Int32 PESignatureOffset = 0;
		try { PESignatureOffset = BitConverter.ToInt32(filebytes, (int)0x3C); }catch {
			return false;
		}
		return (filebytes[PESignatureOffset] == 0x50 && filebytes[PESignatureOffset + 1] == 0x45);
	}

    public static IntPtr Main(byte[] filebytes) {
        if (!IsValidPE(filebytes)) {
            Console.WriteLine("Not a valid PE, skipping...");
            return IntPtr.Zero;
        }

        PEReader PE = new PEReader(filebytes);
        if (PE.Is32BitHeader) {
            Console.WriteLine("Oopsie doopsie,this program doesnt support 32-bit PE,otherwise it will make the program go fucky wucky!");
            return IntPtr.Zero;
        }

        Console.WriteLine("Resolving syscalls needed...");
        SysGate sysgate = new SysGate();
        sysgate.PrepareGateSpace();
        sysgate.CollectSyscalls();

        Console.WriteLine("Mapping PE...");
        IntPtr PEBase = MapPEToMemory(PE, sysgate);
        Console.WriteLine("Resolving imports...");
        ResolveImport(PEBase);
        Console.WriteLine("Resolving delay-imports...");
        ResolveDelayedImport(PEBase);
        Console.WriteLine("Setting memory protections...");
        SetMemoryProtections(PEBase, PE, sysgate);
        Console.WriteLine("Executing TLS callbacks...");
        ExecuteTLSCallback(PEBase);
        Console.WriteLine("Registering exception handler...");
        RegisterExceptionHandler(PEBase);
        Console.WriteLine("Executing entry point...");
        ExecuteEntryPoint(PEBase, PE);

        return PEBase;
    }

	public static IntPtr MapPEToMemory(PEReader PE, SysGate sysgate) {
        NTAVM fSyscallNTAVM = (NTAVM)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTAVM));

        // allocate space for the PE
        IntPtr PEBase = IntPtr.Zero;
        IntPtr PERegionSize = (IntPtr)PE.OptionalHeader64.SizeOfImage;
        sysgate.Gate(SysGate.GetFunctionDJB2Hash("NtAllocateVirtualMemory"));
        fSyscallNTAVM((IntPtr)(-1), ref PEBase, IntPtr.Zero, ref PERegionSize, (UInt32)(AllocationType.Commit | AllocationType.Reserve), (UInt32)PAGE_READWRITE);

        // copy headers
        int PESizeOfHeaders = (int)PE.OptionalHeader64.SizeOfHeaders;
        Marshal.Copy(PE.RawBytes, 0, PEBase, PESizeOfHeaders);

        //Copy Sections
        for (int i = 0; i < PE.FileHeader.NumberOfSections; i++) {
            IntPtr pVASectionBase = (IntPtr)((long)(PEBase.ToInt64() + (int)PE.ImageSectionHeaders[i].VirtualAddress));
            Marshal.Copy(PE.RawBytes, (int)PE.ImageSectionHeaders[i].PointerToRawData, pVASectionBase, (int)PE.ImageSectionHeaders[i].VirtualSize);
        }

        //Perform Base Relocation
        long currentbase = (long)PEBase.ToInt64();
        long delta = (long)(currentbase - (long)PE.OptionalHeader64.ImageBase);
        //Modify Memory Based On Relocation Table
        IntPtr relocationTable = (IntPtr)((long)(PEBase.ToInt64() + (int)PE.OptionalHeader64.BaseRelocationTable.VirtualAddress));
        PEReader.IMAGE_BASE_RELOCATION relocationEntry = new PEReader.IMAGE_BASE_RELOCATION();
        relocationEntry = (PEReader.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(PEReader.IMAGE_BASE_RELOCATION));
        int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(PEReader.IMAGE_BASE_RELOCATION));
        IntPtr nextEntry = relocationTable;
        int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
        IntPtr offset = relocationTable;
        while (true)
        {

            PEReader.IMAGE_BASE_RELOCATION relocationNextEntry = new PEReader.IMAGE_BASE_RELOCATION();
            IntPtr x = (IntPtr)((long)(relocationTable.ToInt64() + (int)sizeofNextBlock));
            relocationNextEntry = (PEReader.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(PEReader.IMAGE_BASE_RELOCATION));
            IntPtr dest = (IntPtr)((long)(PEBase.ToInt64() + (int)relocationEntry.VirtualAdress));
            for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
            {
                IntPtr patchAddr;
                UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));
                UInt16 type = (UInt16)(value >> 12);
                UInt16 fixup = (UInt16)(value & 0xfff);
                switch (type)
                {
                    case 0x0:
                        break;
                    case 0xA:
                        patchAddr = (IntPtr)((long)(dest.ToInt64() + (int)fixup));
                        //Add Delta To Location.
                        long originalAddr = Marshal.ReadInt64(patchAddr);
                        Marshal.WriteInt64(patchAddr, originalAddr + delta);
                        break;
                }
            }
            offset = (IntPtr)((long)(relocationTable.ToInt64() + (int)sizeofNextBlock));
            sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
            relocationEntry = relocationNextEntry;
            nextEntry = (IntPtr)((long)(nextEntry.ToInt64() + (int)sizeofNextBlock));
            if (relocationNextEntry.SizeOfBlock == 0) break; 
        }

        return PEBase;
	}

	public static void ResolveImport(IntPtr PEBase) {
        // parse the initial header of the PE
        IntPtr OptHeader = PEBase + Marshal.ReadInt32((IntPtr)(PEBase + 0x3C)) + 0x18;
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
        }

        // check if current PE have any import(s)
        if ((int)Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)96 + (long)4)) == 0) {
            return;
        }

        // get import table address
        int ImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)12)); //  IMPORT TABLE Size = byte 8 + 4 (4 is the size of the RVA) from the start of the data directory
        IntPtr ImportTableAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 8)); // IMPORT TABLE RVA = byte 8 from the start of the data directory
        int ImportTableCount = (ImportTableSize / 20);

        // iterates through the import tables
        for (int i = 0; i < (ImportTableCount - 1); i++) {
            IntPtr CurrentImportTableAddr = (IntPtr)(ImportTableAddr.ToInt64() + (long)(20 * i));

            string CurrentImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr + 12))).Trim(); // Name RVA = byte 12 from start of the current import table
            if (CurrentImportTableName.StartsWith("api-ms-win")) { // fucking API set schema shit stuff
                continue;
            }

            // get IAT (FirstThunk) and ILT (OriginalFirstThunk) address from Import Table
            IntPtr CurrentImportIATAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentImportTableAddr.ToInt64() + (long)16))); // IAT RVA = byte 16 from the start of the current import table
            IntPtr CurrentImportILTAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32(CurrentImportTableAddr)); // ILT RVA = byte 0 from the start of the current import table

            // get the imported module base address
            IntPtr ImportedModuleAddr = IntPtr.Zero;
            try{ ImportedModuleAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => CurrentImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch{}
            if (ImportedModuleAddr == IntPtr.Zero) { // check if its loaded or not
                ImportedModuleAddr = LoadLibrary(CurrentImportTableName);
                if (ImportedModuleAddr == IntPtr.Zero) {
                       continue;
                }
            }

            // loop through the functions
            for (int z = 0; z < 999999; z++) {
                IntPtr CurrentFunctionILTAddr = (IntPtr)(CurrentImportILTAddr.ToInt64() + (long)(IntPtr.Size * z));
                IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentImportIATAddr.ToInt64()  + (long)(IntPtr.Size * z));

                // check if current ILT is empty
                if (Marshal.ReadIntPtr(CurrentFunctionILTAddr) == IntPtr.Zero) { // the ILT is null, which means we're already on the end of the table
                    break;
                }

                IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionILTAddr)); // reading a union structure for getting the name RVA
                string CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim(); // reading the Name field on the Name table

                
                if (String.IsNullOrEmpty(CurrentFunctionName)) { 
                    continue; // used to silence ntdll's RtlDispatchApc ordinal imported by kernelbase
                }

                // get current function real address
                IntPtr CurrentFunctionRealAddr = GetExportAddress(ImportedModuleAddr, CurrentFunctionName);
                if (CurrentFunctionRealAddr == IntPtr.Zero) {
                    continue;
                }

                try { Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr); }catch{
                    continue;
                }
            }
        }
	}

	public static void ResolveDelayedImport(IntPtr PEBase) {
		// parse the initial header of the PE
        IntPtr OptHeader = PEBase + Marshal.ReadInt32((IntPtr)(PEBase + 0x3C)) + 0x18;
        IntPtr SizeOfHeaders = (IntPtr)Marshal.ReadInt32(OptHeader + 60);
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
        }

        int DelayImportTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)108)); 
        IntPtr DelayImportTableAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 104));
        if (DelayImportTableSize < 1) {
        	return;
        }
        int DelayImportTableCount = DelayImportTableSize / 32;
        
        for (int i = 0; i < (DelayImportTableCount - 1); i++) {
            IntPtr CurrentDelayImportTableAddr = DelayImportTableAddr + (i * 32);

            string CurrentDelayImportTableName = Marshal.PtrToStringAnsi((IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32(CurrentDelayImportTableAddr + 4))).Trim();
            if (CurrentDelayImportTableName.StartsWith("api-ms-win")) { // fucking API set schema shit stuff
                continue;
            }

            IntPtr CurrentDelayImportIATAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentDelayImportTableAddr.ToInt64() + (long)12)));
            IntPtr CurrentDelayImportINTAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)(CurrentDelayImportTableAddr.ToInt64() + (long)16)));

            IntPtr DelayImportedModuleAddr = IntPtr.Zero;
            try{ DelayImportedModuleAddr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => CurrentDelayImportTableName.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch{}
            if (DelayImportedModuleAddr == IntPtr.Zero) { // check if its loaded or not
                DelayImportedModuleAddr = LoadLibrary(CurrentDelayImportTableName);
                if (DelayImportedModuleAddr == IntPtr.Zero) {
                       continue;
                }
            }

            // loop through the functions
            for (int z = 0; z < 999999; z++) {
                IntPtr CurrentFunctionINTAddr = (IntPtr)(CurrentDelayImportINTAddr.ToInt64() + (long)(IntPtr.Size * z));
                IntPtr CurrentFunctionIATAddr = (IntPtr)(CurrentDelayImportIATAddr.ToInt64()  + (long)(IntPtr.Size * z));

                // check if current ILT is empty
                if (Marshal.ReadIntPtr(CurrentFunctionINTAddr) == IntPtr.Zero) { // the INT is null, which means we're already on the end of the table
                    break;
                }

                IntPtr CurrentFunctionNameAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadIntPtr(CurrentFunctionINTAddr)); // reading a union structure for getting the name RVA
                string CurrentFunctionName = Marshal.PtrToStringAnsi(CurrentFunctionNameAddr + 2).Trim(); // reading the Name field on the Name table
                
                if (String.IsNullOrEmpty(CurrentFunctionName)) { 
                    continue; // used to silence ntdll's RtlDispatchApc ordinal imported by kernelbase
                }

                // get current function real address
                IntPtr CurrentFunctionRealAddr = GetExportAddress(DelayImportedModuleAddr, CurrentFunctionName);
                if (CurrentFunctionRealAddr == IntPtr.Zero) {
                    continue;
                }

                try { Marshal.WriteIntPtr(CurrentFunctionIATAddr, CurrentFunctionRealAddr); }catch{
                    continue;
                }
            }
        }
	}

	public static void SetMemoryProtections(IntPtr PEBase, PEReader PE, SysGate sysgate) {
        NTPVM fSyscallNTPVM = (NTPVM)Marshal.GetDelegateForFunctionPointer(sysgate.GatePositionAddress, typeof(NTPVM));

		for (int i = 0; i < PE.FileHeader.NumberOfSections; i++) {
            bool execute = ((uint) PE.ImageSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            bool read = ((uint) PE.ImageSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
            bool write = ((uint) PE.ImageSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            uint protection = PAGE_EXECUTE_READWRITE;

            if (execute && read && write)
            {
                protection = PAGE_EXECUTE_READWRITE;
            }
            else if (!execute && read && write)
            {
                protection = PAGE_READWRITE;
            }
            else if (!write && execute && read)
            {
                protection = PAGE_EXECUTE_READ;
            }
            else if (!execute && !write && read)
            {
                protection = PAGE_READONLY;
            }
            else if (execute && !read && !write)
            {
                protection = PAGE_EXECUTE;
            }
            else if (!execute && !read && !write)
            {
                protection = PAGE_NOACCESS;
            }

            IntPtr TargetPtr = PEBase + (int)PE.ImageSectionHeaders[i].VirtualAddress;
            IntPtr TargetSize = (IntPtr)PE.ImageSectionHeaders[i].VirtualSize;

            uint newProtect = 0;
            sysgate.Gate(SysGate.GetFunctionDJB2Hash("NtProtectVirtualMemory"));
            fSyscallNTPVM((IntPtr)(-1), ref TargetPtr, ref TargetSize, protection, ref newProtect);
        }

        FlushInstructionCache((IntPtr)(-1), IntPtr.Zero, (UIntPtr)0);
	}

    public static void ExecuteTLSCallback(IntPtr PEBase) {
        // parse the initial header of the PE
        IntPtr OptHeader = PEBase + Marshal.ReadInt32((IntPtr)(PEBase + 0x3C)) + 0x18;
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
        }

        int TLSTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)76)); 
        IntPtr TLSTableAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 72));
        if (TLSTableSize < 1) {
            return;
        }
        IntPtr TLSCallbacksAddr = Marshal.ReadIntPtr(TLSTableAddr + (IntPtr.Size * 3)); // smart ass

        for (int i = 0; i < 999999; i++) {
            IntPtr CurrentTLSCallbackAddr = Marshal.ReadIntPtr(TLSCallbacksAddr + (IntPtr.Size * i));
            if (CurrentTLSCallbackAddr == IntPtr.Zero) { // we're at the end of the table
                break;
            }

            IMAGE_TLS_CALLBACK_Delegate CurrentTLSCallback = (IMAGE_TLS_CALLBACK_Delegate)Marshal.GetDelegateForFunctionPointer(CurrentTLSCallbackAddr, typeof(IMAGE_TLS_CALLBACK_Delegate));
            CurrentTLSCallback(PEBase, 1, IntPtr.Zero);
        }
    }

    public static void RegisterExceptionHandler(IntPtr PEBase) {
        IntPtr OptHeader = PEBase + Marshal.ReadInt32((IntPtr)(PEBase + 0x3C)) + 0x18;
        Int16 Magic = Marshal.ReadInt16(OptHeader + 0);
        IntPtr DataDirectoryAddr = IntPtr.Zero;        
        if (Magic == 0x010b) {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x60); // PE32, 0x60 = 96 
        }
        else {
            DataDirectoryAddr = (IntPtr)(OptHeader.ToInt64() + (long)0x70); // PE32+, 0x70 = 112
        }

        int ExceptionHandlerTableSize = Marshal.ReadInt32((IntPtr)(DataDirectoryAddr.ToInt64() + (long)28)); 
        IntPtr ExceptionHandlerTableAddr = (IntPtr)(PEBase.ToInt64() + (long)Marshal.ReadInt32((IntPtr)DataDirectoryAddr + 24));
        if (ExceptionHandlerTableSize < 1) {
            return;
        }

        RtlAddFunctionTable(ExceptionHandlerTableAddr, (UInt32)((ExceptionHandlerTableSize / 12) - 1), PEBase);
    }

    public static void ExecuteEntryPoint(IntPtr PEBase, PEReader PE) {
        if (PE.OptionalHeader64.AddressOfEntryPoint < 1) {
            return;
        }

        // get and calculate AOEP
        IntPtr AOEP = (IntPtr)((long)(PEBase.ToInt64() + (int)PE.OptionalHeader64.AddressOfEntryPoint));
        // create delegate for AOEP and execute it
        DllMainDelegate ExecutePE = (DllMainDelegate)Marshal.GetDelegateForFunctionPointer(AOEP, typeof(DllMainDelegate));
        ExecutePE(PEBase, 1, IntPtr.Zero);
    }
}