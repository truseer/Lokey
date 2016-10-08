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

namespace Lokey
{
    class Create : ISelectedManagementItemModule
    {
        private readonly bool IsPad; // else connection
        private bool IsConnection { get { return !IsPad; } }

        private const string NameConst = "create";
        private const string ChunkSizeFlag = "--chunk_size";
        private const string EncryptedFlag = "--encrypted";
        private const string RngFlag = "--rng";
        private const string RngNameFlag = "--rng";

        public Create(ManagementSelectionType type)
        {
            switch(type)
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

        private string SelectionTypeString() { return IsPad ? "pad" : "connection"; }

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- Create " + SelectionTypeString() + " using default or specified RNG;"
                    + "pad size is specified in bytes; password encrypted if specified"
                };
            }
        }

        public string HelpPrefix
        {
            get
            {
                return NameConst + " <pad_size> [" + ChunkSizeFlag + " <chunk_size>] [" + EncryptedFlag + "] [" + RngFlag + " <rng_uid> | " + RngNameFlag + " <rng_name>]";
            }
        }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd, string selection)
        {
            if(args.Any())
            {
                string size_arg = args.First();
                ulong size = ulong.Parse(size_arg);
                args = args.Skip(1);
                Dictionary<string, SubCommandModule.FlagArg> flags;
                try
                {
                    flags = SubCommandModule.ParseFlagsFromArgs(ref args,
                        new SubCommandModule.FlagArg[] {
                            new SubCommandModule.FlagArg(EncryptedFlag),
                            new SubCommandModule.FlagArg(ChunkSizeFlag, 1),
                            new SubCommandModule.FlagArg(RngFlag, 1),
                            new SubCommandModule.FlagArg(RngNameFlag, 1)
                        });
                }
                catch(InvalidOperationException e)
                {
                    Console.WriteLine(e.Message);
                    return;
                }
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.DefaultRNG;
                int chunkSize = Program.DefaultChunkSize;

                if (flags[ChunkSizeFlag].Found)
                    chunkSize = int.Parse(flags[ChunkSizeFlag].Args.Single());
                
                if(flags[RngFlag].Found)
                {
                    if (flags[RngNameFlag].Found)
                    {
                        Console.WriteLine("Multiple RNGs cannot be specified for " + SelectionTypeString() + " creation.");
                        return;
                    }
                    rng = CryptoAlgorithmCache.Instance.GetRNG(uint.Parse(flags[RngFlag].Args.Single()));
                }
                else if(flags[RngNameFlag].Found)
                {
                    rng = CryptoAlgorithmCache.Instance.GetRNG(flags[RngNameFlag].Args.Single());
                }

                if(IsPad)
                {
                    if (flags[EncryptedFlag].Found)
                        pmd.GenerateEncryptedPad(selection, rng, size, chunkSize);
                    else
                        pmd.GenerateLonePad(selection, rng, size, chunkSize);
                }
                else
                {
                    if (flags[EncryptedFlag].Found)
                        pmd.GenerateEncryptedConnection(selection, rng, size, chunkSize);
                    else
                        pmd.GenerateConnection(selection, rng, size, chunkSize);
                }
            }
            else
            {
                Console.WriteLine("create subcommand requires a size argument (specified in bytes)");
            }
        }
    }
}
