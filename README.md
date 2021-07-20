# BeaEngine_C-Sharp
This project provides a C# interface for the BeaEngine 5.3.0. https://github.com/BeaEngine/beaengine


C# usage as follows:

byte[] byteArray = new byte[] { 0x48, 0x83, 0x3D, 0xC6, 0x8B, 0x00, 0x00, 0x00 };

            List<BeaEngine._Disasm> theList = BeaEngine._Disassemble(byteArray, 0x7FFDCDE61D3A, BeaEngine.Architecture.x86_64);

            for (int i = 0; i < theList.Count; i++)
            {

                BeaEngine._Disasm disasm = theList[i];

                if (disasm.Length < 1 || disasm.Length > 15) // Verify that instruction lenght is within the bounds.
                    continue;

                Console.WriteLine("{0} => {1}", disasm.VirtualAddr.ToString("X16"), disasm.CompleteInstr);
                // 00007FFDCDE61D3A => cmp qword ptr [00007FFDCDE6A908h], 0000000000000000h

            }


