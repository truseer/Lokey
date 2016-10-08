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
    class Update : IManagementModule
    {
        private const string NameConst = "update";
        private const string SaltFlag = "--salt";
        private const string RngFlag = "--rng";
        private const string RngNameFlag = "--rng_name";
        private const string HelpPrefixConst = NameConst + " <new_password> [" 
            + RngFlag + " <rng_uid> | " + RngNameFlag + " <rng_name>] [" + SaltFlag + "]";

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[] {
                    "- Updates the password for the pad amangement directory using the specified RNG; optionally also updates the password salt"
                };
            }
        }

        public string HelpPrefix { get { return HelpPrefixConst; } }

        public string Name { get { return NameConst; } }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ProcessCommand(IEnumerable<string> args, PadManagementDirectory pmd)
        {
            if(args.Any())
            {
                string password = args.First();
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.DefaultRNG;
                args = args.Skip(1);
                Dictionary<string, SubCommandModule.FlagArg> flags;
                try
                {
                    flags = SubCommandModule.ParseFlagsFromArgs(ref args,
                        new SubCommandModule.FlagArg[]
                        {
                            new SubCommandModule.FlagArg(SaltFlag),
                            new SubCommandModule.FlagArg(RngFlag, 1),
                            new SubCommandModule.FlagArg(RngNameFlag, 1)
                        });
                }
                catch(InvalidOperationException e)
                {
                    Console.WriteLine(e.Message);
                    return;
                }
                if(flags[RngFlag].Found)
                {
                    if (flags[RngNameFlag].Found)
                    {
                        Console.WriteLine("RNG can only be specified once for update operation");
                        return;
                    }
                    rng = CryptoAlgorithmCache.Instance.GetRNG(flags[RngFlag].Args.Single());
                }
                else if(flags[RngNameFlag].Found)
                {
                    rng = CryptoAlgorithmCache.Instance.GetRNG(flags[RngNameFlag].Args.Single());
                }
                pmd.UpdateEncryption(password, rng, true, flags[SaltFlag].Found);
            }
            else
            {
                Console.WriteLine("Invalid command, new password must be specified.");
            }
        }
    }
}
