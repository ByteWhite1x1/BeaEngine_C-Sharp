/* 
 * 
 * 
 * Copyright (c) 2014, Carter Jones
 * CopyRight (c) 2021, White Byte at hexderef.com
 * 
 * All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies, 
either expressed or implied, of the FreeBSD Project.
*/

/*
 *  As of 01/2021 fixes as follows by White Byte:
 *  
 *  - Fixed the original structure misalignment that caused unexpected behaviour in managed code
 *  - BeaEngine 5.3.0 compatibility
 */

#define WIN64

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using System.Runtime.ConstrainedExecution;
using System.Runtime;
using System.Runtime.CompilerServices;

using System.Threading;
using System.IO;

using UInt8 = System.Byte;

namespace HEX_DEREF
{

    /// <summary>
    /// A simple C# interface to the BeaEngine library.
    /// </summary>
    public class BeaEngine
    {

        public static volatile Int32 totalDisassembledOpCodes = 0;

        public static Int32 IncrementDisassembledOpCodes(int length)
        {
            // return Interlocked.Increment(ref totalDisassembledOpCodes);
            return Interlocked.Add(ref totalDisassembledOpCodes, length);
        }        

        #region Constants        

        public const byte UD__ = 2;
        public const byte DE__ = 3;

        public const byte ESReg = 1;
        public const byte DSReg = 2;
        public const byte FSReg = 4;
        public const byte GSReg = 8;
        public const byte CSReg = 16;
        public const byte SSReg = 32;

        public const byte InvalidPrefix = 4;
        public const byte SuperfluousPrefix = 2;
        public const byte NotUsedPrefix = 0;
        public const byte MandatoryPrefix = 8;
        public const byte InUsePrefix = 1;

        public const byte LowPosition = 0;
        public const byte HighPosition = 1;

        public const int UnknownOpcode = -1;
        public const int OutOfBlock = -2;
        public const int InstructionLength = 80;

        // EVEX Masking 
        public const byte NO_MASK = 0;
        public const byte MERGING = 1;
        public const byte MERGING_ZEROING = 2;

        // EVEX compressed displacement
        public const byte FULL = 1;
        public const byte HALF = 2;
        public const byte FULL_MEM = 3;
        public const byte TUPLE1_SCALAR__8 = 4;
        public const byte TUPLE1_SCALAR__16 = 5;
        public const byte TUPLE1_SCALAR = 6;
        public const byte TUPLE1_FIXED__32 = 7;
        public const byte TUPLE1_FIXED__64 = 8;
        public const byte TUPLE2 = 9;
        public const byte TUPLE4 = 10;
        public const byte TUPLE8 = 11;
        public const byte HALF_MEM = 12;
        public const byte QUARTER_MEM = 13;
        public const byte EIGHTH_MEM = 14;
        public const byte MEM128 = 15;
        public const byte MOVDDUP = 16;

#if WIN64
        private const string dllName = @"BeaEngine_5.3.0.dll";                

#else
        private const string DllName = "BeaEngine-32.dll";
#endif

        #endregion

        #region Enumerations

        [Flags]
        public enum InstructionSet
        {
            GENERAL_PURPOSE_INSTRUCTION = 0x10000,
            FPU_INSTRUCTION = 0x20000,
            MMX_INSTRUCTION = 0x30000,
            SSE_INSTRUCTION = 0x40000,
            SSE2_INSTRUCTION = 0x50000,
            SSE3_INSTRUCTION = 0x60000,
            SSSE3_INSTRUCTION = 0x70000,
            SSE41_INSTRUCTION = 0x80000,
            SSE42_INSTRUCTION = 0x90000,
            SYSTEM_INSTRUCTION = 0xA0000,
            VM_INSTRUCTION = 0xB0000,
            UNDOCUMENTED_INSTRUCTION = 0xC0000,
            AMD_INSTRUCTION = 0XD0000,
            ILLEGAL_INSTRUCTION = 0XE0000,
            AES_INSTRUCTION = 0xF0000,
            CLMUL_INSTRUCTION = 0x100000,
            AVX_INSTRUCTION = 0x110000,
            AVX2_INSTRUCTION = 0x120000,
            MPX_INSTRUCTION = 0x130000,
            AVX512_INSTRUCTION = 0x140000,
            SHA_INSTRUCTION = 0x150000,
            BMI2_INSTRUCTION = 0x160000,
            CET_INSTRUCTION = 0x170000,
            BMI1_INSTRUCTION = 0x180000,
            XSAVEOPT_INSTRUCTION = 0x190000,
            FSGSBASE_INSTRUCTION = 0x1A0000,
            CLWB_INSTRUCTION = 0x1B0000,
            CLFLUSHOPT_INSTRUCTION = 0x1C0000,
            FXSR_INSTRUCTION = 0x1D0000,
            XSAVE_INSTRUCTION = 0x1E0000,
            SGX_INSTRUCTION = 0x1F0000,
            PCONFIG_INSTRUCTION = 0x200000,
            UINTR_INSTRUCTION = 0x210000,
            KL_INSTRUCTION = 0x220000,
            AMX_INSTRUCTION = 0x230000,
            DATA_TRANSFER = 0x1,
            ARITHMETIC_INSTRUCTION,
            LOGICAL_INSTRUCTION,
            SHIFT_ROTATE,
            BIT_UInt8,
            CONTROL_TRANSFER,
            STRING_INSTRUCTION,
            InOutINSTRUCTION,
            ENTER_LEAVE_INSTRUCTION,
            FLAG_CONTROL_INSTRUCTION,
            SEGMENT_REGISTER,
            MISCELLANEOUS_INSTRUCTION,
            COMPARISON_INSTRUCTION,
            LOGARITHMIC_INSTRUCTION,
            TRIGONOMETRIC_INSTRUCTION,
            UNSUPPORTED_INSTRUCTION,
            LOAD_CONSTANTS,
            FPUCONTROL,
            STATE_MANAGEMENT,
            CONVERSION_INSTRUCTION,
            SHUFFLE_UNPACK,
            PACKED_SINGLE_PRECISION,
            SIMD128bits,
            SIMD64bits,
            CACHEABILITY_CONTROL,
            FP_INTEGER_CONVERSION,
            SPECIALIZED_128bits,
            SIMD_FP_PACKED,
            SIMD_FP_HORIZONTAL,
            AGENT_SYNCHRONISATION,
            PACKED_ALIGN_RIGHT,
            PACKED_SIGN,
            PACKED_BLENDING_INSTRUCTION,
            PACKED_TEST,
            PACKED_MINMAX,
            HORIZONTAL_SEARCH,
            PACKED_EQUALITY,
            STREAMING_LOAD,
            INSERTION_EXTRACTION,
            DOT_PRODUCT,
            SAD_INSTRUCTION,
            ACCELERATOR_INSTRUCTION,    /* crc32, popcnt (sse4.2) */
            ROUND_INSTRUCTION
        }

        public enum InstructionType
        {
            DATA_TRANSFER = 0x1,
            ARITHMETIC_INSTRUCTION,
            LOGICAL_INSTRUCTION,
            SHIFT_ROTATE,
            BIT_UInt8,
            CONTROL_TRANSFER,
            STRING_INSTRUCTION,
            InOutINSTRUCTION,
            ENTER_LEAVE_INSTRUCTION,
            FLAG_CONTROL_INSTRUCTION,
            SEGMENT_REGISTER,
            MISCELLANEOUS_INSTRUCTION,
            COMPARISON_INSTRUCTION,
            LOGARITHMIC_INSTRUCTION,
            TRIGONOMETRIC_INSTRUCTION,
            UNSUPPORTED_INSTRUCTION,
            LOAD_CONSTANTS,
            FPUCONTROL,
            STATE_MANAGEMENT,
            CONVERSION_INSTRUCTION,
            SHUFFLE_UNPACK,
            PACKED_SINGLE_PRECISION,
            SIMD128bits,
            SIMD64bits,
            CACHEABILITY_CONTROL,
            FP_INTEGER_CONVERSION,
            SPECIALIZED_128bits,
            SIMD_FP_PACKED,
            SIMD_FP_HORIZONTAL,
            AGENT_SYNCHRONISATION,
            PACKED_ALIGN_RIGHT,
            PACKED_SIGN,
            PACKED_BLENDING_INSTRUCTION,
            PACKED_TEST,
            PACKED_MINMAX,
            HORIZONTAL_SEARCH,
            PACKED_EQUALITY,
            STREAMING_LOAD,
            INSERTION_EXTRACTION,
            DOT_PRODUCT,
            SAD_INSTRUCTION,
            ACCELERATOR_INSTRUCTION,    /* crc32, popcnt (sse4.2) */
            ROUND_INSTRUCTION
        }

        [Flags]
        public enum EFlagsStates
        {
            TE_ = 1,
            MO_ = 2,
            RE_ = 4,
            SE_ = 8,
            UN_ = 0x10,
            PR_ = 0x20
        }

        public enum BranchType
        {
            JO = 1, // https://www.aldeid.com/wiki/X86-assembly/Instructions/jo
            JC = 2,
            JE = 3, // https://www.aldeid.com/wiki/X86-assembly/Instructions/jz
            JA = 4, // https://www.aldeid.com/wiki/X86-assembly/Instructions/ja
            JS = 5, // https://www.aldeid.com/wiki/X86-assembly/Instructions/js
            JP = 6,
            JL = 7, // https://www.aldeid.com/wiki/X86-assembly/Instructions/jl
            JG = 8, // https://www.aldeid.com/wiki/X86-assembly/Instructions/jg
            JB = 2, /* JC == JB */ // https://www.aldeid.com/wiki/X86-assembly/Instructions/jb
            JECXZ = 10,
            JmpType = 11,
            CallType = 12,
            RetType = 13,
            JNO = -1,
            JNC = -2,
            JNE = -3, // https://www.aldeid.com/wiki/X86-assembly/Instructions/jnz
            JNA = -4,
            JNS = -5,
            JNP = -6,
            JNL = -7,
            JNG = -8,
            JNB = -9
        }

        [Flags]
        public enum ArgumentDetails : int
        {
            NO_ARGUMENT = 0x10000,
            REGISTER_TYPE = 0x20000,
            MEMORY_TYPE = 0x30000,
            CONSTANT_TYPE = 0x40000,
            GENERAL_REG = 0x1,
            MMX_REG = 0x2,
            SSE_REG = 0x4,
            AVX_REG = 0x8,
            AVX512_REG = 0x10,
            SPECIAL_REG = 0x20,
            CR_REG = 0x40,
            DR_REG = 0x80,
            MEMORY_MANAGEMENT_REG = 0x100,
            MPX_REG = 0x200,
            OPMASK_REG = 0x400,
            SEGMENT_REG = 0x800,
            FPU_REG = 0x1000,
            TMM_REG = 0x2000,
            RELATIVE_ = 0x4000000,
            ABSOLUTE_ = 0x8000000,
            READ = 0x1,
            WRITE = 0x2,
            REG0 = 0x1,
            REG1 = 0x2,
            REG2 = 0x4,
            REG3 = 0x8,
            REG4 = 0x10,
            REG5 = 0x20,
            REG7 = 0x80,
            REG8 = 0x100,
            REG9 = 0x200,
            REG10 = 0x400,
            REG11 = 0x800,
            REG12 = 0x1000,
            REG13 = 0x2000,
            REG14 = 0x4000,
            REG15 = 0x8000,
            REG16 = 0x10000,
            REG17 = 0x20000,
            REG18 = 0x40000,
            REG19 = 0x80000,
            REG20 = 0x100000,
            REG21 = 0x200000,
            REG22 = 0x400000,
            REG23 = 0x800000,
            REG24 = 0x1000000,
            REG25 = 0x2000000,
            REG26 = 0x4000000,
            REG27 = 0x8000000,
            REG28 = 0x10000000,
            REG29 = 0x20000000,
            REG30 = 0x40000000,
            REG31 = unchecked((int)0x80000000)
        }

        [Flags]
        public enum RegisterId : short
        {
            REG0 = 0x1, // RAX
            REG1 = 0x2, // RCX
            REG2 = 0x4, // RDX
            REG3 = 0x8, // RBX
            REG4 = 0x10, // RSP
            REG5 = 0x20, // RBP
            REG6 = 0x40, // RSI
            REG7 = 0x80, // RDI
            REG8 = 0x100, // R8
            REG9 = 0x200, // R9
            REG10 = 0x400, // R10
            REG11 = 0x800, // R11
            REG12 = 0x1000, // R12
            REG13 = 0x2000, // R13
            REG14 = 0x4000, // R14
            REG15 = unchecked((short)0x8000) // R15
        }

        public enum AccessMode
        {
            READ = 0x1,
            WRITE = 0x2,
        }

        [Flags]
        public enum SpecialInfo : ulong
        {
            /* === mask = 0xff */
            NoTabulation = 0x00000000,
            Tabulation = 0x00000001,

            /* === mask = 0xff00 */
            MasmSyntax = 0x00000000,
            GoAsmSyntax = 0x00000100,
            NasmSyntax = 0x00000200,
            ATSyntax = 0x00000400,

            /* === mask = 0xff0000 */
            PrefixedNumeral = 0x00010000,
            SuffixedNumeral = 0x00000000,

            /* === mask = 0xff000000 */
            ShowSegmentRegs = 0x01000000
        }

        public enum Architecture : uint
        {
            x86_32 = 0,
            x86_64 = 64
        }

        #endregion

        #region Properties

        public static string Version
        {
            get
            {
                return Marshal.PtrToStringAnsi(BeaEngine.BeaEngineVersion());
            }
        }

        public static string Revision
        {
            get
            {
                return Marshal.PtrToStringAnsi(BeaEngine.BeaEngineRevision());
            }
        }

        #endregion

        #region Methods

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "Disasm")]
        public static extern int Disassemble(ref _Disasm instruction);

        // https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/yield

        // [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static IEnumerable<_Disasm> Disassemble(byte[] bytes, UInt64 address, Architecture architecture, bool benchmark)
        {

            GCHandle h = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            UInt64 endOfCodeSection = (UInt64)h.AddrOfPinnedObject().ToInt64() + (ulong)bytes.Length;

            _Disasm d = new _Disasm();

            d.EIP = (UIntPtr)h.AddrOfPinnedObject().ToInt64();
            d.VirtualAddr = address;
            d.Archi = architecture;

            bool error = false;

            while (!error)
            {

                d.SecurityBlock = (uint)(endOfCodeSection - d.EIP.ToUInt64());

                d.Length = BeaEngine.Disassemble(ref d);

                if (d.Length == BeaEngine.UnknownOpcode || d.Length == BeaEngine.OutOfBlock)
                {
                    d.EIP = d.EIP + 1;
                    d.VirtualAddr = d.VirtualAddr + 1;
                }                
                else
                {

                    _Disasm yieldedInst = d;

                    IncrementDisassembledOpCodes(yieldedInst.Length); // Disassembled op codes / sec                    

                    // Console.WriteLine("{0} {1} [{2}]", yieldedInst.VirtualAddr.ToString("X"), yieldedInst.CompleteInstr, yieldedInst.Length);

                    d.EIP = d.EIP + d.Length;
                    d.VirtualAddr = d.VirtualAddr + (ulong)d.Length;

                    if (d.EIP.ToUInt64() >= endOfCodeSection)
                    {
                        error = true;
                    }

                    // You use a yield return statement to return each element one at a time.

                    if (!benchmark)
                        yield return yieldedInst;

                }

            }

            h.Free();

            yield break;

        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        public static List<_Disasm> _Disassemble(byte[] bytes, UInt64 address, Architecture architecture)
        {

            List<_Disasm> theList = new List<_Disasm>();

            GCHandle h = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            UInt64 endOfCodeSection = (UInt64)h.AddrOfPinnedObject().ToInt64() + (ulong)bytes.Length;

            _Disasm d = new _Disasm();

            d.EIP = (UIntPtr)h.AddrOfPinnedObject().ToInt64();
            d.VirtualAddr = address;
            d.Archi = architecture;

            bool error = false;

            while (!error)
            {

                d.SecurityBlock = (uint)(endOfCodeSection - d.EIP.ToUInt64());

                d.Length = BeaEngine.Disassemble(ref d);

                if (d.Length == BeaEngine.OutOfBlock)
                {
                    error = true;
                }
                else if (d.Length == BeaEngine.UnknownOpcode)
                {
                    d.EIP = d.EIP + 1;
                    d.VirtualAddr = d.VirtualAddr + 1;
                }
                else
                {

                    _Disasm myInst = d;
                    theList.Add(myInst);

                    d.EIP = d.EIP + d.Length;
                    d.VirtualAddr = d.VirtualAddr + (ulong)d.Length;

                    if (d.EIP.ToUInt64() >= endOfCodeSection)
                    {
                        error = true;
                    }

                }

            }

            h.Free();

            return theList;

        }

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr BeaEngineVersion();

        [DllImport(dllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr BeaEngineRevision();

        #endregion

        #region Structures

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MEMORYTYPE
        {
            public Int64 BaseRegister;
            public Int64 IndexRegister;
            public Int32 Scale;
            public Int64 Displacement;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct OPTYPE
        {

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)]
            public string OpMnemonic;
            public Int64 OpType;
            public Int32 OpSize;
            public Int32 OpPosition;
            public UInt32 AccessMode;
            public MEMORYTYPE Memory;
            public REGISTERTYPE Registers;
            public UInt32 SegmentReg;

            public ArgumentDetails Details
            {
                get { return (ArgumentDetails)(0xFFFF0000 & this.OpType); }
            }

            public RegisterId RegisterId
            {
                get { return (RegisterId)(0x0000FFFF & this.OpType); }
            }

        }

        // https://devblogs.microsoft.com/oldnewthing/20200103-00/?p=103290
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _Disasm
        {
            public UIntPtr EIP;
            public UInt64 VirtualAddr;
            public UInt32 SecurityBlock;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = InstructionLength)]
            public string CompleteInstr;
            public Architecture Archi;
            public SpecialInfo Options;
            public INSTRTYPE Instruction;
            public OPTYPE Operand1;
            public OPTYPE Operand2;
            public OPTYPE Operand3;
            public OPTYPE Operand4;
            public OPTYPE Operand5;
            public OPTYPE Operand6;
            public OPTYPE Operand7;
            public OPTYPE Operand8;
            public OPTYPE Operand9;
            public PrefixInfo Prefix;
            public InternalDatas Reserved_;

            /// <summary>
            /// A place to optionally store the length of an instruction.
            /// </summary>
            public int Length { get; set; }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct REGISTERTYPE
        {
            public Int64 Type;
            public Int64 Gpr;
            public Int64 Mmx;
            public Int64 Xmm;
            public Int64 Ymm;
            public Int64 Zmm;
            public Int64 Special;
            public Int64 Cr;
            public Int64 Dr;
            public Int64 MemManagement;
            public Int64 Mpx;
            public Int64 OpMask;
            public Int64 Segment;
            public Int64 Fpu;
            public Int64 Tmm;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct INSTRTYPE
        {
            public Int32 Category;
            public Int32 Opcode;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 24)]
            public string Mnemonic;
            public Int32 BranchType;
            public EFLStruct Flags;
            public UInt64 AddrValue;
            public Int64 Immediat;
            REGISTERTYPE ImplicitModifiedRegs;
            REGISTERTYPE ImplicitUsedRegs;

            public InstructionSet InstructionSet
            {
                get { return (InstructionSet)(0xFFFF0000 & this.Category); }
            }

            public InstructionType InstructionType
            {
                get { return (InstructionType)(0x0000FFFF & this.Category); }
            }

        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct EFLStruct
        {
            public UInt8 OF_;
            public UInt8 SF_;
            public UInt8 ZF_;
            public UInt8 AF_;
            public UInt8 PF_;
            public UInt8 CF_;
            public UInt8 TF_;
            public UInt8 IF_;
            public UInt8 DF_;
            public UInt8 NT_;
            public UInt8 RF_;
            public UInt8 Alignment;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PrefixInfo
        {
            public int Number;
            public int NbUndefined;
            public UInt8 LockPrefix;
            public UInt8 OperandSize;
            public UInt8 AddressSize;
            public UInt8 RepnePrefix;
            public UInt8 RepPrefix;
            public UInt8 FSPrefix;
            public UInt8 SSPrefix;
            public UInt8 GSPrefix;
            public UInt8 ESPrefix;
            public UInt8 CSPrefix;
            public UInt8 DSPrefix;
            public UInt8 BranchTaken;
            public UInt8 BranchNotTaken;
            public REX_Struct REX;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 2)]
            public string Unknown;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct REX_Struct
        {
            public UInt8 W_;
            public UInt8 R_;
            public UInt8 X_;
            public UInt8 B_;
            public UInt8 State;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct VEX_Struct
        {
            public UInt8 L;
            public UInt8 vvvv;
            public UInt8 mmmmm;
            public UInt8 pp;
            public UInt8 state;
            public UInt8 opcode;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MemoryType
        {
            public Int64 BaseRegister;
            public Int64 IndexRegister;
            public Int32 Scale;
            public Int64 Displacement;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct EVEX_Struct
        {
            public UInt8 P0;
            public UInt8 P1;
            public UInt8 P2;
            public UInt8 Mm;
            public UInt8 Pp;
            public UInt8 R;
            public UInt8 X;
            public UInt8 B;
            public UInt8 R1;
            public UInt8 Vvvv;
            public UInt8 V;
            public UInt8 Aaa;
            public UInt8 W;
            public UInt8 Z;
            public UInt8 b;
            public UInt8 LL;
            public UInt8 State;
            public UInt8 Masking;
            public UInt8 Tupletype;

        }

        /* reserved structure used for thread-safety */
        /* unusable by customer */
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct InternalDatas
        {
            public IntPtr EIP_;
            public UInt64 EIP_VA;
            public UIntPtr EIP_REAL;
            public Int32 OriginalOperandSize;
            public Int32 OperandSize;
            public Int32 MemDecoration;
            public Int32 AddressSize;
            public Int32 MOD_;
            public Int32 RM_;
            public Int32 INDEX_;
            public Int32 SCALE_;
            public Int32 BASE_;
            public Int32 REGOPCODE;
            public UInt32 DECALAGE_EIP;
            public Int32 FORMATNUMBER;
            public Int32 SYNTAX_;
            public UInt64 EndOfBlock;
            public Int32 RelativeAddress;
            public UInt32 Architecture;
            public Int32 ImmediatSize;
            public Int32 NB_PREFIX;
            public Int32 PrefRepe;
            public Int32 PrefRepne;
            public UInt32 SEGMENTREGS;
            public UInt32 SEGMENTFS;
            public Int32 third_arg;
            public UInt64 OPTIONS;
            public Int32 ERROR_OPCODE;
            public REX_Struct REX;
            public Int32 OutOfBlock;
            public VEX_Struct VEX;
            public EVEX_Struct EVEX;
            public Int32 VSIB_;
            public Int32 Register_;
        }

        #endregion
    }

}
