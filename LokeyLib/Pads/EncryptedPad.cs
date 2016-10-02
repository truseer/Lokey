﻿/*********************************************************************/
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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LokeyLib
{
    public class EncryptedPad : AbstractPad
    {
        private FileInfo pad;
        private List<PadChunk> usedChunks = new List<PadChunk>();
        private byte[] padKey;
        private byte[] padIv;
        private byte[] headerKey;
        private byte[] headerIv;
        private long footerOffset;

        private EncryptedPad(FileInfo file, byte[] headerKey, byte[] headerIv, byte[] padKey, byte[] padIv, long footerOffset)
        {
            pad = file;
            this.headerIv = headerIv;
            this.headerKey = headerKey;
            this.padIv = padIv;
            this.padKey = padKey;
            this.footerOffset = footerOffset;
            ReadChunkList();
        }

        /******************************************************************
        | Header prepended to the encrypted file.                         |
        *******************************************************************
        | Description                    | Size (Bytes)      | Encryption |
        *******************************************************************
        | Header IV                      | 16                | None       |
        | Footer Offset                  | 8                 | AES256CTR  |
        | Pad IV                         | 16                | AES256CTR  |
        | Pad Key                        | 32                | AES256CTR  |
        ******************************************************************/

        /******************************************************************
        | Footer appended to the encrypted file.                          |
        *******************************************************************
        | Description               | Size (Bytes)      | Encryption      |
        *******************************************************************
        | Used Key Chunks           | 16 x N            | AES256CTR (Pad) |
        ******************************************************************/

        public const int KeyLength = Aes256Ctr.KeySizeBytes;
        public const string DefaultExt = ".epad";

        private const int HeaderIvLength = Aes256Ctr.IvSizeBytes;
        private const int HeaderKeyLength = KeyLength;
        private const int PadIvLength = Aes256Ctr.IvSizeBytes;
        private const int PadKeyLength = KeyLength;
        private const int FooterOffsetLength = sizeof(long);
        private const int EncryptedHeaderLength = PadIvLength + PadKeyLength + FooterOffsetLength;
        private const int HeaderLength = EncryptedHeaderLength + HeaderIvLength;

        static private Aes256Ctr encryptor = new Aes256Ctr();

        public static EncryptedPad Create(string filePath, byte[] key, IPadDataGenerator rng, ulong length, int chunkSize = 4096)
        {
            ulong longChunkSize = (chunkSize <= 0) ? 4096UL : (ulong) chunkSize;
            byte[] headerIv = rng.GetPadData(HeaderIvLength);
            byte[] padKey = rng.GetPadData(PadKeyLength);
            byte[] padIv = rng.GetPadData(PadIvLength);
            long footerOffset = HeaderLength + (long)length;
            byte[] footerOffsetBytes = BitConverter.GetBytes(footerOffset);
            byte[] encryptedHeaderBytes = new byte[EncryptedHeaderLength];
            Array.Copy(footerOffsetBytes, encryptedHeaderBytes, FooterOffsetLength);
            Array.Copy(padIv, 0, encryptedHeaderBytes, FooterOffsetLength, PadIvLength);
            Array.Copy(padKey, 0, encryptedHeaderBytes, FooterOffsetLength + PadIvLength, PadKeyLength);
            encryptedHeaderBytes = encryptor.EncryptBytes(key, headerIv, encryptedHeaderBytes, true);
            using (FileStream fs = File.Open(filePath, FileMode.CreateNew, FileAccess.Write))
            {
                fs.Write(headerIv, 0, HeaderIvLength);
                fs.Write(encryptedHeaderBytes, 0, EncryptedHeaderLength);
                ulong padBytesWritten = 0UL;
                while(padBytesWritten < length)
                {
                    ulong bytesLeftToWrite = length - padBytesWritten;
                    ulong bytesToWrite = bytesLeftToWrite < longChunkSize ? bytesLeftToWrite : longChunkSize;
                    byte[] padChunk = encryptor.EncryptBytesAtOffset(padKey, padIv, padBytesWritten, rng.GetPadData(bytesToWrite));
                    fs.Write(padChunk, 0, padChunk.Length);
                    padBytesWritten += bytesToWrite;
                }
            }
            return new EncryptedPad(new FileInfo(filePath), key, headerIv, padKey, padIv, footerOffset);
        }

        public static EncryptedPad Load(FileInfo padFile, byte[] key)
        {
            using (FileStream fs = padFile.Open(FileMode.Open, FileAccess.Read))
            {
                byte[] headerIv = new byte[HeaderIvLength];
                int bytesRead = 0;
                while (bytesRead < headerIv.Length)
                {
                    int numBytes = fs.Read(headerIv, bytesRead, headerIv.Length - bytesRead);
                    if (numBytes <= 0)
                        throw new InvalidEncryptedFileHeaderException("The header could not be read.");
                    bytesRead += numBytes;
                }
                byte[] encryptedHeader = new byte[EncryptedHeaderLength];
                bytesRead = 0;
                while (bytesRead < encryptedHeader.Length)
                {
                    int numBytes = fs.Read(encryptedHeader, bytesRead, encryptedHeader.Length - bytesRead);
                    if (numBytes <= 0)
                        throw new InvalidEncryptedFileHeaderException("The header could not be read.");
                    bytesRead += numBytes;
                }
                encryptedHeader = encryptor.DecryptBytes(key, headerIv, encryptedHeader, true);
                long footerOffset = BitConverter.ToInt64(encryptedHeader, 0);
                byte[] padIv = new byte[PadIvLength];
                Array.Copy(encryptedHeader, FooterOffsetLength, padIv, 0, padIv.Length);
                byte[] padKey = new byte[PadKeyLength];
                Array.Copy(encryptedHeader, FooterOffsetLength + padIv.Length, padKey, 0, padKey.Length);
                return new EncryptedPad(padFile, key, headerIv, padKey, padIv, footerOffset);
            }
        }

        public override string Identifier { get { return pad.FullName; } }

        public override bool IsValid { get { return pad.Exists; } }

        public override ulong PadSize { get { return (ulong)footerOffset - HeaderLength; } }

        public override IEnumerable<PadChunk> UnusedChunks { get { return usedChunks.Complement(PadSize); } }

        public override byte[] GetPadBytes(ulong start, ulong size)
        {
            if (start + size > PadSize)
                throw new InsufficientPadException("The pad bytes requested extend past the end of the pad.");
            byte[] bytes = new byte[size];
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Read))
            {
                fs.Position = (long)start + HeaderLength;
                ulong bytesRead = (ulong)fs.Read(bytes, 0, size < int.MaxValue ? (int)size : int.MaxValue);
                while (bytesRead < size)
                {
                    ulong bytesLeftToRead = size - bytesRead;
                    int bytesToRead = bytesLeftToRead < int.MaxValue ? (int)bytesLeftToRead : int.MaxValue;
                    byte[] bufferToRead = new byte[bytesToRead];
                    int bytesReadToBuffer = fs.Read(bufferToRead, 0, bytesToRead);
                    if(bytesReadToBuffer <= 0)
                        throw new InsufficientPadException("The pad file could not be read.");
                    Array.Copy(bufferToRead, 0L, bytes, (long)bytesRead, bytesReadToBuffer);
                    bytesRead += (ulong)bytesReadToBuffer;
                }
            }
            bytes = encryptor.DecryptBytesAtOffset(padKey, padIv, start, bytes, true);
            usedChunks.Add(new PadChunk(start, size));
            WriteChunkList();
            return bytes;
        }

        public void UnsafeDelete()
        {
            pad.Delete();
        }

        private void WriteChunkList()
        {
            SimplifyChunkList();
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Write))
            {
                fs.Position = footerOffset;
                ulong padOffset = PadSize;
                foreach (PadChunk chunk in usedChunks)
                {
                    byte[] chunkBytes = chunk.ToBytes();
                    chunkBytes = encryptor.EncryptBytesAtOffset(padKey, padIv, padOffset, chunkBytes);
                    fs.Write(chunkBytes, 0, chunkBytes.Length);
                    padOffset += (ulong)chunkBytes.Length;
                }
            }
        }

        private void ReadChunkList()
        {
            usedChunks.Clear();
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Read))
            {
                fs.Position = footerOffset;
                byte[] padChunkBuf = new byte[PadChunk.BytesSize];
                ulong chunkPosition = PadSize;
                int bytesRead = fs.Read(padChunkBuf, 0, padChunkBuf.Length);
                while (bytesRead > 0)
                {
                    if (bytesRead != PadChunk.BytesSize)
                        throw new InvalidEncryptedFileHeaderException("The footer has an incorrect size.");
                    padChunkBuf = encryptor.DecryptBytesAtOffset(padKey, padIv, chunkPosition, padChunkBuf, true);
                    usedChunks.Add(PadChunk.FromBytes(padChunkBuf));
                    chunkPosition += (ulong)bytesRead;
                    bytesRead = fs.Read(padChunkBuf, 0, padChunkBuf.Length);
                }
            }
            SimplifyChunkList();
        }

        private void SimplifyChunkList()
        {
            if (usedChunks.Count > 1)
            {
                usedChunks = usedChunks.Simplify().ToList();
            }
        }

#if DEBUG
        private const string ClassName = "EncryptedPad";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            EncryptedPad pad = null;
            try
            {
                bool testsSucceeded = true;
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.GetRNG(1);
                byte[] key = rng.GetPadData(KeyLength);
                FileInfo file = UtilityFunctions.GenerateTestPlaintextFile("test.bin", 1 << 15);
                try
                {
                    pad = Create("test" + DefaultExt, key, rng, 1U << 26);
                    foreach(ICryptoAlgorithmFactory factory in CryptoAlgorithmCache.Instance.Algorithms)
                    {
                        FileInfo testCopy = file.CopyTo("test2.bin");
                        try
                        {
                            EncryptedFile eFile = EncryptedFile.CreateFromPlaintextFile(testCopy, pad, factory);
                            eFile.Encrypt();
                            testsSucceeded &= WriteTestResult(factory.Name + " Encryption", !UtilityFunctions.FilesEqual(file, testCopy));
                            FileInfo eCopy = testCopy.CopyTo("test3.bin");
                            try
                            {
                                EncryptedFile ptFile = EncryptedFile.CreateFromEncryptedFile(eCopy, pad);
                                ptFile.Decrypt();
                                testsSucceeded &= WriteTestResult(factory.Name + " Decryption", UtilityFunctions.FilesEqual(file, eCopy));
                            }
                            finally
                            {
                                eCopy.Delete();
                            }
                        }
                        finally
                        {
                            testCopy.Delete();
                        }
                    }
                    testsSucceeded &= WriteTestResult("Template", true);
                    return testsSucceeded;
                }
                finally
                {
                    file.Delete();
                }
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
                    try { pad.UnsafeDelete(); }
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
