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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LokeyLib
{
#if DEBUG
    public
#else
    internal
#endif
    class FileBlockEnumerable : IEnumerable<byte[]>
    {
        private class FileBlockEnumerator : IEnumerator<byte[]>
        {
            public FileBlockEnumerator(int blockSize, FileStream fs, long startingPosition)
            {
                this.startingPosition = startingPosition;
                this.blockSize = blockSize;
                this.fs = fs;
                position = startingPosition;

            }

            private readonly int blockSize;
            private FileStream fs;
            private byte[] currentBlock = null;
            private long position;
            private readonly long startingPosition;

            public bool MoveNext()
            {
                currentBlock = new byte[blockSize];
                fs.Position = position;
                int bytesRead = fs.Read(currentBlock, 0, blockSize);
                position = fs.Position;
                Array.Resize(ref currentBlock, bytesRead);
                return bytesRead > 0;
            }

            public void Reset()
            {
                currentBlock = null;
                position = startingPosition;
            }

            public byte[] Current { get { return currentBlock; } }

            object IEnumerator.Current { get { return currentBlock; } }

            public void Dispose() { }
        }

        public FileBlockEnumerable(FileStream fs, int blockSize, long startingPosition)
        {
            this.startingPosition = startingPosition;
            this.blockSize = blockSize;
            this.fs = fs;
        }

        private readonly int blockSize;
        private FileStream fs;
        private readonly long startingPosition;

        public IEnumerator<byte[]> GenerateEnumerator()
        {
            return new FileBlockEnumerator(blockSize, fs, startingPosition);
        }

        public IEnumerator<byte[]> GetEnumerator()
        {
            return GenerateEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GenerateEnumerator();
        }

#if DEBUG
        private const string ClassName = "FileBlockEnumerable";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            FileInfo testFile = null;
            try
            {
                bool testsSucceeded = true;
                testFile = UtilityFunctions.GenerateTestPlaintextFile("test.bin", 256 * 10);
                using (FileStream fs = testFile.Open(FileMode.Open, FileAccess.ReadWrite))
                {
                    FileBlockEnumerable fbe = new FileBlockEnumerable(fs, 128, 0);
                    byte[] block1 = new byte[128];
                    byte[] block2 = new byte[128];
                    int i;
                    for (i = 0; i < block1.Length; ++i) block1[i] = (byte)i;
                    for (; i - block1.Length < block2.Length; ++i) block2[i - block1.Length] = (byte)i;
                    byte[] nextBlock = block1;
                    int fbnum = 1;
                    foreach(byte[] fileBlock in fbe)
                    {
                        testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(nextBlock, fileBlock));
                        nextBlock = nextBlock == block1 ? block2 : block1;
                    }
                    nextBlock = block1;
                    fbnum = 1;
                    foreach (byte[] fileBlock in new BufferedEnumerable<byte[]>(3, fbe))
                    {
                        testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(nextBlock, fileBlock));
                        nextBlock = nextBlock == block1 ? block2 : block1;
                    }
                    nextBlock = block1;
                    fbnum = 1;
                    BufferedEnumerable<byte[]> buff = new BufferedEnumerable<byte[]>(3, fbe);
                    fs.Position = 0L;
                    for (i = 0; i < 128 * 3; ++i) fs.WriteByte(0);
                    foreach (byte[] fileBlock in buff)
                    {
                        testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(nextBlock, fileBlock));
                        nextBlock = nextBlock == block1 ? block2 : block1;
                    }
                    fs.Position = 0L;
                    for (i = 0; i < 256 * 10; ++i) fs.WriteByte(0);
                    fbnum = 1;
                    byte[] zBlock = new byte[128];
                    for (i = 0; i < 128; ++i) zBlock[i] = 0;
                    testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(buff.First(), block1));
                    testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(buff.Skip(1).First(), block2));
                    testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(buff.Skip(2).First(), block1));
                    foreach (byte[] fileBlock in buff.Skip(3))
                    {
                        testsSucceeded &= WriteTestResult("File Block " + fbnum++.ToString() + " Check", UtilityFunctions.ByteArraysEqual(zBlock, fileBlock));
                    }
                }
                return testsSucceeded;
            }
            catch (Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                if (testFile != null)
                    testFile.Delete();
                UtilityFunctions.WriteTestsHeaderFooter(ClassName, false);
            }
        }

        private static bool WriteTestResult(string testName, bool success)
        {
            return UtilityFunctions.WriteTestResult(ClassName, testName, success);
        }
#endif
    }
}
