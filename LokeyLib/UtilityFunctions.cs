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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
#if DEBUG
    public
#else
    internal 
#endif
    static class UtilityFunctions
    {
        public static string GetRelativePath(string from, string to)
        {
            Uri fromPath = new Uri(from);
            Uri toPath = new Uri(to);
            Uri relativeUri = fromPath.MakeRelativeUri(toPath);
            return relativeUri.OriginalString;
        }

        public static bool FilesEqual(FileInfo a, FileInfo b, int blockSize = 4096)
        {
            byte[] aBlock = new byte[blockSize];
            byte[] bBlock = new byte[blockSize];
            using (FileStream fsA = a.OpenRead())
            {
                using (FileStream fsB = b.OpenRead())
                {
                    int bytesRead;
                    do
                    {
                        bytesRead = fsA.Read(aBlock, 0, blockSize);
                        if (fsB.Read(bBlock, 0, blockSize) != bytesRead)
                            return false;
                        for (int i = 0; i < bytesRead; ++i)
                        {
                            if (aBlock[i] != bBlock[i])
                                return false;
                        }
                    } while (bytesRead > 0);
                }
            }
            return true;
        }

        public static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a.LongLength != b.LongLength)
                return false;
            for(long i = 0L; i < a.LongLength; ++i)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
#if DEBUG
        internal static bool WriteTestResult(string className, string testName, bool success)
        {
            Console.Write("\t");
            Console.Write(className);
            Console.Write(" ");
            Console.Write(testName);
            Console.Write(" Test: ");
            Console.WriteLine(success ? "Passed" : "Failed");
            return success;
        }

        internal static void WriteTestsHeaderFooter(string className, bool header)
        {
            Console.Write("---------- ");
            Console.Write(header ? "Begin" : "End");
            Console.Write(" ");
            Console.Write(className);
            Console.WriteLine(" Tests ----------");
        }

        internal static void WriteTestExceptionFailure(string className, Exception e)
        {
            Console.Write("!!!!!!!!!! ");
            Console.Write(className);
            Console.Write(" Test Failed with Exception: ");
            Console.WriteLine(e.ToString());
        }


        internal static FileInfo GenerateTestPlaintextFile(string filepath, int size)
        {
            FileInfo file = new FileInfo(filepath);
            using (FileStream fs = file.Open(FileMode.Create, FileAccess.Write))
            {
                for (int i = 0; i < size; ++i)
                {
                    fs.WriteByte((byte)(i % 256));
                }
            }
            return new FileInfo(file.FullName);
        }
#endif
    }
}
