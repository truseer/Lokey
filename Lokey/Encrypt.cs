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
    class Encrypt : ISelectedManagementItemModule
    {
        private readonly bool IsPad; // else connection
        private bool IsConnection { get { return !IsPad; } }

        public Encrypt(ManagementSelectionType type)
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

        private const string ConstName = "encrypt";
        private const string CipherFlag = "--cipher";
        private const string CipherNameFlag = "--cipher_name";
        private const string ChunkSizeFlag = "--chunk_size";
        private const string PreserveNameFlag = "--preserve_name";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- Encrypt file using selected cipher"
                };
            }
        }

        public string HelpPrefix
        {
            get
            {
                return ConstName + " <file> [" + PreserveNameFlag + "] [" 
                    + CipherFlag + " <cipher_uid> | " + CipherNameFlag 
                    + " <cipher_name>] [" + ChunkSizeFlag + " <chunk_size>]";
            }
        }

        public string Name { get { return ConstName; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd, string selection)
        {
            if (args.Any())
            {
                string filePath = args.First();
                args = args.Skip(1);
                int chunkSize = Program.DefaultChunkSize;
                ICryptoAlgorithmFactory alg = CryptoAlgorithmCache.Instance.DefaultCryptoAlgorithm;
                Dictionary<string, SubCommandModule.FlagArg> flags;
                try
                {
                    flags = SubCommandModule.ParseFlagsFromArgs(ref args,
                        new SubCommandModule.FlagArg[] {
                            new SubCommandModule.FlagArg(PreserveNameFlag),
                            new SubCommandModule.FlagArg(CipherFlag, 1),
                            new SubCommandModule.FlagArg(CipherNameFlag, 1),
                            new SubCommandModule.FlagArg(ChunkSizeFlag, 1)
                        });
                } 
                catch(InvalidOperationException e)
                {
                    Console.WriteLine(e.Message);
                    return;
                }
                if (args.Any())
                {
                    Console.Write("Unknown arguments passed to " + Name + " subcommand: ");
                    Console.WriteLine(SubCommandModule.JoinArgs(args));
                }
                else
                {
                    if (flags[ChunkSizeFlag].Found)
                        chunkSize = int.Parse(flags[ChunkSizeFlag].Args.Single());
                    if (flags[CipherFlag].Found)
                    {
                        if (flags[CipherNameFlag].Found)
                        {
                            Console.WriteLine("Cipher cannot be specified multiple times for encrypt operation.");
                            return;
                        }
                        alg = CryptoAlgorithmCache.Instance.GetAlgorithm(uint.Parse(flags[CipherFlag].Args.Single()));
                    }
                    else if (flags[CipherNameFlag].Found)
                    {
                        alg = CryptoAlgorithmCache.Instance.GetAlgorithm(flags[CipherFlag].Args.Single());
                    }
                    NamePackedFile npf = new NamePackedFile(filePath);
                    if (!npf.FileNameIsPacked && !flags[PreserveNameFlag].Found)
                        npf.PackFileName();
                    FileInfo file = new FileInfo(npf.FilePath);
                    if (IsPad)
                    {
                        pmd.EncryptFileFromPad(selection, file, alg, chunkSize);
                    }
                    else
                    {
                        pmd.EncryptFileFromConnection(selection, file, alg, chunkSize);
                    }
                    Console.Write("\"");
                    Console.Write(filePath);
                    Console.Write("\" encrypted to: \"");
                    Console.Write(npf.FilePath);
                    Console.WriteLine("\".");
                }
            }
            else
            {
                Console.WriteLine("");
            }
        }
    }
}
