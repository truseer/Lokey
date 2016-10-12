//***********************************************************************/
// LokeyLib - A library for the management and use of cryptographic pads
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

using System.IO;
using System.Security.Cryptography;

namespace LokeyLib
{
    public abstract class AbstractSystemCryptoHashAlgorithm : IHashAlgorithm
    {
        public AbstractSystemCryptoHashAlgorithm(HashAlgorithm algorithm)
        {
            alg = algorithm;
        }

        private HashAlgorithm alg;

        public int HashSize { get { return alg.HashSize / 8; } }

        public abstract string Name { get; }

        public abstract uint UID { get; }

        public byte[] ComputeHash()
        {
            byte[] emptyArray = new byte[0];
            alg.TransformFinalBlock(emptyArray, 0, 0);
            return alg.Hash;
        }

        public byte[] ComputeHash(Stream stream)
        {
            return alg.ComputeHash(stream);
        }

        public void ProcessBuffer(byte[] buffer)
        {
            int offset = 0;
            while(offset < buffer.Length)
                offset += alg.TransformBlock(buffer, offset, buffer.Length - offset, buffer, offset);
        }

#if DEBUG
        protected abstract string ClassName { get; }

        protected abstract AbstractSystemCryptoHashAlgorithm GenerateNewCopy();

        protected abstract HashAlgorithm GenerateUnderlying();

        protected static bool RunTest(AbstractSystemCryptoHashAlgorithm algorithm)
        {
            UtilityFunctions.WriteTestsHeaderFooter(algorithm.ClassName, true);
            try
            {
                bool result = true;
                System.Console.Write(algorithm.Name);
                System.Console.Write(": ( HashSize : ");
                System.Console.Write(algorithm.HashSize);
                System.Console.Write(" bytes / ");
                System.Console.Write(algorithm.HashSize * 8);
                System.Console.Write(" bits ), ( UID : ");
                System.Console.Write(algorithm.UID);
                System.Console.WriteLine(" )");
                System.Random rand = new System.Random();
                byte[] testbuf = new byte[rand.Next(256, 1024)];
                rand.NextBytes(testbuf);
                AbstractSystemCryptoHashAlgorithm testAlgorithm = algorithm.GenerateNewCopy();
                HashAlgorithm underlyingAlgorithm = algorithm.GenerateUnderlying();
                result &= UtilityFunctions.WriteTestResult(algorithm.ClassName, "Hash Length", testAlgorithm.HashSize * 8 == underlyingAlgorithm.HashSize);
                byte[] referenceHash = underlyingAlgorithm.ComputeHash(testbuf);
                using (MemoryStream ms = new MemoryStream(testbuf))
                {
                    byte[] streamHash = testAlgorithm.ComputeHash(ms);
                    result &= UtilityFunctions.WriteTestResult(algorithm.ClassName, "Stream Compute Hash", UtilityFunctions.ByteArraysEqual(referenceHash, streamHash));
                }
                testAlgorithm = algorithm.GenerateNewCopy();
                testAlgorithm.ProcessBuffer(testbuf);
                byte[] testhash = testAlgorithm.ComputeHash();
                result &= UtilityFunctions.WriteTestResult(algorithm.ClassName, "Single Chunk Compute Hash", UtilityFunctions.ByteArraysEqual(referenceHash, testhash));
                testAlgorithm = algorithm.GenerateNewCopy();
                int offset = 0;
                while (offset < testbuf.Length)
                {
                    int size = rand.Next(1, testbuf.Length / 2);
                    if (size + offset > testbuf.Length)
                        size = testbuf.Length - offset;
                    byte[] chunk = new byte[size];
                    System.Array.Copy(testbuf, offset, chunk, 0, size);
                    testAlgorithm.ProcessBuffer(chunk);
                    offset += size;
                }
                testhash = testAlgorithm.ComputeHash();
                result &= UtilityFunctions.WriteTestResult(algorithm.ClassName, "Multiple Chunk Compute Hash", UtilityFunctions.ByteArraysEqual(referenceHash, testhash));
                return result;
            }
            catch (System.Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(algorithm.ClassName, e);
                return false;
            }
            finally
            {
                UtilityFunctions.WriteTestsHeaderFooter(algorithm.ClassName, false);
            }
        }
#endif
    }
}
