//***********************************************************************/
// Lokey - A tool for the management and use of cryptographic pads
//***********************************************************************/
// Copyright (C) 2016  Ian Doyle
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//***********************************************************************/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LokeyLib;
using System.IO;

namespace Lokey
{
    class Decrypt : ISelectedManagementItemModule
    {
        private readonly bool IsPad; // else connection
        private bool IsConnection { get { return !IsPad; } }

        public Decrypt(ManagementSelectionType type)
        {
            switch (type)
            {
                case ManagementSelectionType.Conection:
                    IsPad = false;
                    break;
                case ManagementSelectionType.Pad:
                    IsPad = true;
                    break;
                default:
                    throw new InvalidOperationException("Invalid management selection type");
            }
        }

        private const string NameConst = "decrypt";
        private const string ChunkFlag = "--chunk_size";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- Decrypt File"
                };
            }
        }

        public string HelpPrefix
        {
            get
            {
                return NameConst + " <file> [" + ChunkFlag + " <chunk_size>]";
            }
        }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd, string selection)
        {
            if (args.Any())
            {
                string filePath = args.First();
                args = args.Skip(1);
                FileInfo file = new FileInfo(filePath);
                int chunkSize = Program.DefaultChunkSize;
                Dictionary<string, SubCommandModule.FlagArg> flags;
                try
                {
                    flags = SubCommandModule.ParseFlagsFromArgs(ref args,
                        new SubCommandModule.FlagArg[] {
                            new SubCommandModule.FlagArg(ChunkFlag, 1) });
                }
                catch(InvalidOperationException e)
                {
                    Console.WriteLine(e.Message);
                    return;
                }
                if(args.Any())
                {
                    Console.WriteLine("Unknown arguments passed to " + NameConst + " subcommand");
                }
                if (flags[ChunkFlag].Found)
                    chunkSize = int.Parse(flags[ChunkFlag].Args.Single());
                if (IsPad)
                {
                    pmd.DecryptFileFromPad(selection, file, chunkSize);
                }
                else
                {
                    pmd.DecryptFileFromConnection(selection, file, chunkSize);
                }
                NamePackedFile namePack = new NamePackedFile(filePath);
                if (namePack.FileNameIsPacked)
                    namePack.UnpackFileName();
                Console.Write("\"");
                Console.Write(filePath);
                Console.Write("\" decrypted to: \"");
                Console.Write(namePack.FilePath);
                Console.WriteLine("\".");
            }
            else
            {
                Console.WriteLine(NameConst + " subcommand requires a file argument.");
            }
        }
    }
}
