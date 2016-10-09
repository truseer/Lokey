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

using LokeyLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lokey
{
    class Mgmt : ICommandModule
    {
        private Dictionary<string, IManagementModule> submodules = new IManagementModule[] {
            new Connection(),
            new Pad(),
            new Update()
        }.ToDictionary(mod => mod.Name);

        public const string NameConst = "mgmt";

        private const string PasswordFlag = "--password";
        private const string RngFlag = "--rng";
        private const string RngNameFlag = "--rng_name";
        private const string HelpPrefixConst = NameConst + " " + HelpArgs;
        public const string HelpArgs = "<root_directory> [" + PasswordFlag + " <password>] ["
            + RngNameFlag + " <rng_name> | " + RngFlag + " <UID>]";

        public string Name { get { return NameConst; } }

        public string HelpPrefix { get { return HelpPrefixConst; } }

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- list all pads and connections; does not use a key/password"
                };
            }
        }

        public Dictionary<string, ISubCommandModule> Submodules
        {
            get { return submodules.Values.Cast<ISubCommandModule>().ToDictionary(m => m.Name); }
        }

        public static PadManagementDirectory ParseArgs(ref IEnumerable<string> args)
        {
            if (args.Any())
            {
                DirectoryInfo mgmtDir = new DirectoryInfo(args.First());
                args = args.Skip(1);
                string password = null;
                IPadDataGenerator rng = null;
                Dictionary<string, SubCommandModule.FlagArg> flags;
                try
                {
                    flags = SubCommandModule.ParseFlagsFromArgs(ref args,
                        new SubCommandModule.FlagArg[] {
                        new SubCommandModule.FlagArg(PasswordFlag, 1),
                        new SubCommandModule.FlagArg(RngFlag, 1),
                        new SubCommandModule.FlagArg(RngNameFlag, 1)
                        });
                }
                catch (InvalidOperationException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }

                if (flags[RngFlag].Found)
                {
                    if (flags[RngNameFlag].Found)
                    {
                        Console.WriteLine("RNG cannot be specified twice for pad management directory load");
                        return null;
                    }
                    rng = CryptoAlgorithmCache.Instance.GetRNG(uint.Parse(flags[RngFlag].Args.Single()));
                }
                else if (flags[RngNameFlag].Found)
                {
                    rng = CryptoAlgorithmCache.Instance.GetRNG(flags[RngFlag].Args.Single());
                }

                if (flags[PasswordFlag].Found)
                    password = flags[PasswordFlag].Args.Single();

                PadManagementDirectory pmd = password == null
                    ? new PadManagementDirectory(mgmtDir, (byte[])null, rng)
                    : new PadManagementDirectory(mgmtDir, password, rng);
                return pmd;
            }
            else
            {
                Console.WriteLine("A root directory must be specified for the mgmt directory.");
            }
            return null;
        }

        public void ProcessCommand(IEnumerable<string> args, Dictionary<string, ISubCommandModule> unused)
        {
            PadManagementDirectory pmd = ParseArgs(ref args);
            if (pmd != null)
            {
                if (args.Any())
                {
                    IManagementModule mgmtMod;
                    if (submodules.TryGetValue(args.First(), out mgmtMod))
                    {
                        mgmtMod.ProcessCommand(args.Skip(1), pmd);
                    }
                    else
                    {
                        Console.WriteLine(args.First() + " is an invalid argument");
                    }
                }
                else
                {
                    Console.Write("Pad Management Directory Rooted at \"");
                    Console.Write(pmd.PadRootPath);
                    Console.WriteLine("\" contains:");
                    Console.WriteLine("Connections:");
                    foreach (string connName in pmd.ConnectionNames)
                        Console.WriteLine(connName);
                    Console.WriteLine("Standalone Pads:");
                    foreach (string padId in pmd.LonePadIDs)
                        Console.WriteLine(padId);
                }
            }
        }
    }
}
