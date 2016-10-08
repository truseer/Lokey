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
    class Connection : IManagementModule
    {
        private Dictionary<string, ISelectedManagementItemModule> submodules = new ISelectedManagementItemModule[]
        {
            new Create(ManagementSelectionType.Conection),
            new Encrypt(ManagementSelectionType.Conection),
            new Decrypt(ManagementSelectionType.Conection),
            new Twin()
        }.ToDictionary(m => m.Name);

        public const string NameConst = "connection";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- List information on specified connection"
                };
            }
        }

        public string HelpPrefix { get { return NameConst + " <connection_name>"; } }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules
        {
            get { return submodules.Values.Cast<ISubCommandModule>().ToDictionary(sc => sc.Name); }
        }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd)
        {
            if (args.Any())
            {
                string connectionName = args.First();
                args = args.Skip(1);
                if (args.Any())
                {
                    ISelectedManagementItemModule submod;
                    if (submodules.TryGetValue(args.First(), out submod))
                    {
                        submod.ProcessCommand(args.Skip(1), pmd, connectionName);
                    }
                    else
                    {
                        Console.WriteLine("Invalid subcommand \"" + args.First() + "\" to " + NameConst);
                    }
                }
                else
                {
                    IPadConnection connection = pmd.Connections.Single(conn => conn.Name.Equals(connectionName));
                    WriteConnectionInfo(connection);
                }
            }
            else
            {
                Console.WriteLine(NameConst + " subcommand requires a connection name argument.");
            }
        }

        public static void WriteConnectionInfo(IPadConnection connection, string indent = "")
        {
            Console.Write("Information for connection \"");
            Console.Write(connection.Name);
            Console.WriteLine("\":");
            Console.WriteLine("From Pad:");
            Pad.WritePadInfo(connection.From, indent + "\t");
            Console.WriteLine("To Pad:");
            Pad.WritePadInfo(connection.To, indent + "\t");
        }
    }
}
