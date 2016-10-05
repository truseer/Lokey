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

using System;
using System.Security.Cryptography;

namespace LokeyLib
{
    public class Aes256Ctr
    {
        private AesManaged aes = new AesManaged()
        {
            KeySize = KeySizeBits,
            Mode = CipherMode.ECB,
            Padding = PaddingMode.None,
            BlockSize = BlockSizeBits
        };

        public const int KeySizeBits = 256;
        public const int KeySizeBytes = KeySizeBits / 8;
        public const int IvSizeBytes = BlockSizeBytes;

        private const int BlockSizeBits = 128;
        private const int BlockSizeBytes = BlockSizeBits / 8;

        public Aes256Ctr() { }

        public byte[] EncryptBytes(byte[] key, byte[] iv, byte[] plaintext, bool encryptInPlace = false)
        {
            return EncryptBytesAtOffset(key, iv, 0UL, plaintext, encryptInPlace);
        }

        public byte[] DecryptBytes(byte[] key, byte[] iv, byte[] ciphertext, bool decryptInPlace = false)
        {
            return EncryptBytesAtOffset(key, iv, 0UL, ciphertext, decryptInPlace);
        }

        public byte[] EncryptBytesAtOffset(byte[] key, byte[] iv, ulong offset, byte[] plaintext, bool encryptInPlace = false)
        {
            ulong startingBlock = offset / BlockSizeBytes;
            int startingBlockByteOffset = (int)(offset % BlockSizeBytes);
            AesCtrNonce counter = new AesCtrNonce(iv);
            counter.SetCounter(0UL, startingBlock);
            byte[] ciphertext = encryptInPlace ? plaintext : new byte[plaintext.LongLength];
            using (ICryptoTransform xform = aes.CreateEncryptor(key, aes.IV))
            {
                long bytesProcessed = 0;
                byte[] ctrbytes = null;
                byte[] xformedBytes = new byte[BlockSizeBytes];
                int numXformedBytes = 0;
                while(startingBlockByteOffset > 0)
                {
                    ctrbytes = counter.GetBytes(BlockSizeBytes);
                    numXformedBytes = xform.TransformBlock(ctrbytes, 0, BlockSizeBytes, xformedBytes, 0);
                    for (int i = startingBlockByteOffset; i < numXformedBytes && bytesProcessed < ciphertext.LongLength; ++i, ++bytesProcessed)
                    {
                        ciphertext[bytesProcessed] = (byte)(plaintext[bytesProcessed] ^ xformedBytes[i]);
                    }
                    startingBlockByteOffset -= numXformedBytes;
                }
                while(bytesProcessed < ciphertext.LongLength)
                {
                    ctrbytes = counter.GetBytes(BlockSizeBytes);
                    numXformedBytes = xform.TransformBlock(ctrbytes, 0, BlockSizeBytes, xformedBytes, 0);
                    for (int i = 0; i < numXformedBytes && bytesProcessed < ciphertext.LongLength; ++i, ++bytesProcessed)
                    {
                        ciphertext[bytesProcessed] = (byte)(plaintext[bytesProcessed] ^ xformedBytes[i]);
                    }
                }
                Array.Clear(xformedBytes, 0, xformedBytes.Length);
            }
            return ciphertext;
        }

        public byte[] DecryptBytesAtOffset(byte[] key, byte[] iv, ulong offset, byte[] ciphertext, bool decryptInPlace = false)
        {
            return EncryptBytesAtOffset(key, iv, offset, ciphertext, decryptInPlace);
        }

#if DEBUG
        private const string ClassName = "Aes256Ctr";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            SimplePad pad = null;
            try
            {
                bool testsSucceeded = true;
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.GetRNG(1U);
                pad = SimplePad.Create(new System.IO.FileInfo("test" + SimplePad.DefaultExt), new System.IO.FileInfo("test" + SimplePadIndex.DefaultExt), rng, 1UL << 26);
                Aes256Ctr ctr = new Aes256Ctr();
                Aes256CtrPadIvAlgorithm ctrAlg = new Aes256CtrPadIvAlgorithm();
                byte[] testPt = rng.GetPadData(1UL << 14);
                PadChunk keyChunk = new PadChunk(0UL, Aes256Ctr.KeySizeBytes + Aes256Ctr.IvSizeBytes);
                byte[] testCt1 = ctrAlg.Encrypt(pad, keyChunk, testPt);
                byte[] iv = pad.GetPadBytes(0UL, Aes256Ctr.IvSizeBytes);
                byte[] key = pad.GetPadBytes(Aes256Ctr.IvSizeBytes, Aes256Ctr.KeySizeBytes);
                byte[] testCt2 = ctr.EncryptBytes(key, iv, testPt);
                testsSucceeded &= WriteTestResult("Encryption", UtilityFunctions.ByteArraysEqual(testCt1, testCt2));
                byte[] testPt2 = ctrAlg.Decrypt(pad, keyChunk, testCt1);
                byte[] testPt3 = ctr.DecryptBytes(key, iv, testCt2);
                testsSucceeded &= WriteTestResult("Decryption 1", UtilityFunctions.ByteArraysEqual(testPt, testPt2));
                testsSucceeded &= WriteTestResult("Decryption 2", UtilityFunctions.ByteArraysEqual(testPt, testPt3));
                byte[] offsetPt = new byte[testPt.Length - 2000];
                Array.Copy(testPt, 2000, offsetPt, 0, offsetPt.Length);
                byte[] offsetCt = ctr.EncryptBytesAtOffset(key, iv, 2000, offsetPt);
                byte[] offsetCtCopy = new byte[offsetCt.Length];
                Array.Copy(testCt1, 2000, offsetCtCopy, 0, offsetCtCopy.Length);
                testsSucceeded &= WriteTestResult("Offset Encryption", UtilityFunctions.ByteArraysEqual(offsetCt, offsetCtCopy));
                byte[] offsetPtDecrypted = ctr.DecryptBytesAtOffset(key, iv, 2000, offsetCt);
                testsSucceeded &= WriteTestResult("Offset Decryption", UtilityFunctions.ByteArraysEqual(offsetPt, offsetPtDecrypted));
                return testsSucceeded;
            }
            catch (Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                if (pad != null)
                {
                    try { pad.NonsecureDelete(); }
                    catch (Exception e) { UtilityFunctions.WriteTestExceptionFailure(ClassName, e); }
                }
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
