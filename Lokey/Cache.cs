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
using LokeyLib;

namespace Lokey
{
    class Cache : ICommandModule
    {
        public const string NameConst = "cache";

        public string Name { get { return NameConst; } }

        public string HelpPrefix { get { return NameConst; } }

        public IEnumerable<string> HelpLines
        {
            get
            {
                return new string[]
                {
                    "- list all available ciphers and random number generators",
                    "cipher - list available encryption algorithms",
                    "cipher [cipher names or UIDs] - list available encryption algorithms",
                    "rng - list available random number generators",
                    "rng [RNG names or UIDs] - list random number generators with matching names or UIDs"
                };
            }
        }

        public Dictionary<string, ISubCommandModule> Submodules { get { return new Dictionary<string, ISubCommandModule>(0); } }

        public void ListAlgorithms()
        {
            ListAlgorithms(alg => true);
        }

        public void ListAlgorithms(Func<ICryptoAlgorithmFactory, bool> predicate)
        {
            Console.WriteLine("UID : Name");
            foreach (ICryptoAlgorithmFactory alg in CryptoAlgorithmCache.Instance.Algorithms.Where(predicate))
            {
                Console.Write(alg.UID);
                Console.Write(" : ");
                Console.WriteLine(alg.Name);
            }
        }

        public void ListRNGs()
        {
            ListRNGs(alg => true);
        }

        public void ListRNGs(Func<IPadDataGenerator, bool> predicate)
        {
            Console.WriteLine("UID : Name");
            foreach (IPadDataGenerator rng in CryptoAlgorithmCache.Instance.RNGs.Where(predicate))
            {
                Console.Write(rng.UID);
                Console.Write(" : ");
                Console.WriteLine(rng.Name);
            }
        }

        public void ProcessCommand(IEnumerable<string> args, Dictionary<string, ISubCommandModule> unused)
        {
            if(args.Any())
            {
                string arg = args.First();
                IEnumerable<string> extraArgs = args.Skip(1);
                switch (arg)
                {
                    case "cipher":
                        if (extraArgs.Any())
                            ListAlgorithms(alg => extraArgs.Any(extraArg => extraArg == alg.Name.ToLowerInvariant() || extraArg == alg.UID.ToString()));
                        else
                            ListAlgorithms();
                        break;
                    case "rng":
                        if (extraArgs.Any())
                            ListRNGs(rng => extraArgs.Any(extraArg => extraArg == rng.Name.ToLowerInvariant() || extraArg == rng.UID.ToString()));
                        else
                            ListRNGs();
                        break;
                    default:
                        Console.WriteLine("Invalid argument \"" + arg + "\" to \"lokey cache\"");
                        break;
                }
            }
            else
            {
                Console.WriteLine("Ciphers:");
                ListAlgorithms();
                Console.WriteLine();
                Console.WriteLine("RNGs:");
                ListRNGs();
            }
        }
    }
}
