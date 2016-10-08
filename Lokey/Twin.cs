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
    class Twin : ISelectedManagementItemModule
    {
        private const string NameConst = "twin";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- Twin the connection to the target drectory"
                };
            }
        }

        public string HelpPrefix { get { return NameConst + " <target_directory>"; } }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd, string selection)
        {
            if(args.Any())
            {
                string dirPath = args.Single();
                DirectoryInfo tgtdir = new DirectoryInfo(dirPath);
                if (pmd.Connections.Single(conn => conn.Name.Equals(selection)) is IEncryptionPadObject)
                {
                    throw new NotImplementedException("Twin not implemented for encrypted pads");
                }
                pmd.TwinConnection(selection, tgtdir);
            }
            else
            {
                Console.WriteLine("The twin subcommand requires a target directory argument");
            }
        }
    }
}
