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

namespace Lokey
{
    class Program
    {
        public const string Name = "lokey";
        public const int DefaultChunkSize = 8192;

        static Dictionary<string, ICommandModule> modules = new ICommandModule[]
        {
            new Cache(),
            new Mgmt(),
            new Help()
        }.ToDictionary(mod => mod.Name);

        static void Main(string[] args)
        {
            ICommandModule module;
            if (args.Any() && modules.TryGetValue(args[0].ToLowerInvariant(), out module))
            {
                module.ProcessCommand(args.Skip(1).Select(arg => arg.ToLowerInvariant()),
                    modules.Values.Cast<ISubCommandModule>().ToDictionary(m => m.Name));
            }
            else
            {
                Console.WriteLine("Unknown command, try \"" + Name + " " + Help.NameString + "\"");
            }
        }
    }
}
