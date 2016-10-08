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
    class Pad : IManagementModule
    {
        private Dictionary<string, ISelectedManagementItemModule> submodules = new ISelectedManagementItemModule[] 
        {
            new Create(ManagementSelectionType.Pad),
            new Encrypt(ManagementSelectionType.Pad),
            new Decrypt(ManagementSelectionType.Pad)
        }.ToDictionary(m => m.Name);

        public const string NameConst = "pad";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- List information on specified pad"
                };
            }
        }

        public string HelpPrefix { get { return NameConst + " <pad_id>"; } }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules
        {
            get { return submodules.Values.Cast<ISubCommandModule>().ToDictionary(sc => sc.Name); }
        }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd)
        {
            if(args.Any())
            {
                string padId = args.First();
                args = args.Skip(1);
                if (args.Any())
                {
                    ISelectedManagementItemModule submod;
                    if (submodules.TryGetValue(args.First(), out submod))
                    {
                        submod.ProcessCommand(args.Skip(1), pmd, padId);
                    }
                    else
                    {
                        Console.WriteLine("Invalid subcommand \"" + args.First() + "\" to " + NameConst);
                    }
                }
                else
                {
                    AbstractPad pad = pmd.LonePads.Single(p => p.Identifier.ToLowerInvariant().Equals(padId));
                    WritePadInfo(pad);
                }
            }
            else
            {
                Console.WriteLine(NameConst + " subcommand requires a pad ID argument.");
            }
        }

        public static void WritePadInfo(AbstractPad pad, string indent = "")
        {
            Console.Write(indent);
            Console.Write("Information for pad \"");
            Console.Write(pad.Identifier);
            Console.WriteLine("\":");

            Console.Write(indent);
            Console.Write("Pad Size: ");
            Console.WriteLine(pad.PadSize);

            Console.Write(indent);
            Console.Write("Unused Pad Size: ");
            Console.WriteLine(pad.UnusedChunks.Select(chunk => chunk.Size).Sum(ul => (long)ul));

            Console.Write(indent);
            Console.WriteLine("Component Files:");
            foreach (FileInfo file in pad.ComponentFiles)
            {
                Console.Write(indent);
                Console.Write("\t");
                Console.WriteLine(file.FullName);
            }
        }
    }
}
