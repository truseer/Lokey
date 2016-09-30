/*********************************************************************/
//LokeyLib - A library for the management and use of cryptographic pads
/*********************************************************************/
//Copyright (C) 2016  Ian Doyle
//
//This program is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program.  If not, see <http://www.gnu.org/licenses/>.
/*********************************************************************/


﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LokeyLib;
using System.IO;

namespace PadTest
{
    class Program
    {

        static void Main(string[] args)
        {
#if DEBUG
            bool testsPassed = true;

            testsPassed &= SimplePad.RunTest();
            testsPassed &= MultiPad.RunTest();
            testsPassed &= CryptoAlgorithmCache.RunTest();
            testsPassed &= FileBlockEnumerable.RunTest();
            testsPassed &= EncryptedFile.RunTest();
			// The following expects you to have two identical, empty USB sticks connected
            testsPassed &= CryptoStick.RunTest();

            Console.WriteLine();
            Console.WriteLine("=======================================================");
            Console.WriteLine("=======================================================");
            Console.WriteLine();
            if(!testsPassed)
                Console.Write("Not ");
            Console.WriteLine("All tests passed!");
            Console.WriteLine();
            Console.WriteLine("=======================================================");
#else
            Console.WriteLine("Build in DEBUG. Tests are not built in RELEASE builds.");
#endif
            Console.ReadKey();
        }
    }
}
