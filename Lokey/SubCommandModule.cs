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
    static class SubCommandModule
    {
        public class FlagArg
        {
            public readonly string Flag;
            public readonly int NumArgs;
            public bool Found = false;
            public IEnumerable<string> Args = null;

            public FlagArg(string flag, int numArgs = 0)
            {
                Flag = flag;
                NumArgs = numArgs;
            }
        }

        public static Dictionary<string, FlagArg> ParseFlagsFromArgs(ref IEnumerable<string> args, IEnumerable<FlagArg> flagDefinitions)
        {
            Dictionary<string, FlagArg> flagsLookup = flagDefinitions.ToDictionary(flg => flg.Flag);
            FlagArg foundFlag;
            while(args.Any() && flagsLookup.TryGetValue(args.First(), out foundFlag))
            {
                if (foundFlag.Found)
                    throw new InvalidOperationException(foundFlag.Flag + " cannot be set more than once.");
                args = args.Skip(1);
                foundFlag.Found = true;
                if (foundFlag.NumArgs > 0)
                {
                    foundFlag.Args = args.Take(foundFlag.NumArgs);
                    args = args.Skip(foundFlag.NumArgs);
                }
                else
                {
                    foundFlag.Args = Enumerable.Empty<string>();
                }
            }
            return flagsLookup;
        }

        public static IEnumerable<string> GetHelpText(this ISubCommandModule module)
        {
            return module.HelpLines.Concat(module.Submodules.Values.SelectMany(submodule => submodule.GetHelpText()))
                .Select(line => module.HelpPrefix + " " + line);
        }

        public static string JoinArgs(this IEnumerable<string> args)
        {
            return args.Aggregate(new StringBuilder(),
                (sb, arg) => { sb.Append(arg); sb.Append(" "); return sb; },
                sb => sb.ToString());
        }
    }
}
