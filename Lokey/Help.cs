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

namespace Lokey
{
    class Help : ICommandModule
    {
        public const string NameString = "help";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- Print help",
                    "<command> - Print help for the specified command"
                };
            }
        }

        public string HelpPrefix { get { return NameString; } }

        public string Name { get { return NameString; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        private IEnumerable<string> GetModuleHelpLines(IEnumerable<string> args, Dictionary<string, ISubCommandModule> modules)
        {
            ISubCommandModule module;
            if(modules.TryGetValue(args.First(), out module))
            {
                args = args.Skip(1);
                if(args.Any())
                    return GetModuleHelpLines(args, module.Submodules).Select(line => module.HelpPrefix + " " + line);
                else
                    return module.GetHelpText();
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        public void ProcessCommand(IEnumerable<string> args, Dictionary<string, ISubCommandModule> modules)
        {
            if(args.Any())
            {
                try
                {
                    foreach (string line in GetModuleHelpLines(args, modules).Select(line => Program.Name + " " + line))
                    {
                        Console.WriteLine(line);
                        Console.WriteLine();
                    }
                }
                catch (InvalidOperationException)
                { 
                    Console.Write("Unknown command: ");
                    Console.WriteLine(args.JoinArgs());
                }
            }
            else
            {
                Console.WriteLine("lokey - a command line interface for interacting with encryption pads");
                foreach(string line in modules.Values.OrderBy(mod => mod.Name).SelectMany(module => module.GetHelpText()))
                {
                    Console.Write(Program.Name);
                    Console.Write(" ");
                    Console.WriteLine(line);
                    Console.WriteLine();
                }
            }
        }
    }
}
