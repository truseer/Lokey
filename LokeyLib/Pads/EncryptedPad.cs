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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LokeyLib
{
    public class EncryptedPad : AbstractPad, IEncryptionPadObject
    {
        private FileInfo pad;
        private List<PadChunk> usedChunks = new List<PadChunk>();
        private byte[] padKey;
        private byte[] padIv;
        private byte[] headerKey;
        private byte[] headerIv;
        private long footerOffset;
        private IPadDataGenerator rng; 

        private EncryptedPad(FileInfo file, byte[] headerKey, byte[] headerIv, byte[] padKey, byte[] padIv, long footerOffset, IPadDataGenerator rng)
        {
            pad = file;
            this.headerIv = headerIv;
            this.headerKey = headerKey;
            this.padIv = padIv;
            this.padKey = padKey;
            this.footerOffset = footerOffset;
            this.rng = rng;
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

        private static byte[] BuildEncryptedHeader(byte[] headerIv, byte[] headerKey, long footerOffset, byte[] padIv, byte[] padKey)
        {
            byte[] footerOffsetBytes = BitConverter.GetBytes(footerOffset);
            byte[] encryptedHeaderBytes = new byte[EncryptedHeaderLength];
            Array.Copy(footerOffsetBytes, encryptedHeaderBytes, FooterOffsetLength);
            Array.Copy(padIv, 0, encryptedHeaderBytes, FooterOffsetLength, PadIvLength);
            Array.Copy(padKey, 0, encryptedHeaderBytes, FooterOffsetLength + PadIvLength, PadKeyLength);
            return encryptor.EncryptBytes(headerKey, headerIv, encryptedHeaderBytes, true);
        }

        private static void WriteHeader(FileStream fs, byte[] headerIv, byte[] encryptedHeaderBytes)
        {
            fs.Write(headerIv, 0, HeaderIvLength);
            fs.Write(encryptedHeaderBytes, 0, EncryptedHeaderLength);
        }

        private void WriteHeader(FileStream fs)
        {
            WriteHeader(fs, headerIv, BuildEncryptedHeader());
        }

        private byte[] BuildEncryptedHeader()
        {
            return BuildEncryptedHeader(headerIv, headerKey, footerOffset, padIv, padKey);
        }

        public static EncryptedPad Create(string filePath, byte[] key, IPadDataGenerator rng, ulong length, int chunkSize = 4096)
        {
            ulong longChunkSize = (chunkSize <= 0) ? 4096UL : (ulong) chunkSize;
            byte[] headerIv = rng.GetPadData(HeaderIvLength);
            byte[] padKey = rng.GetPadData(PadKeyLength);
            byte[] padIv = rng.GetPadData(PadIvLength);
            long footerOffset = HeaderLength + (long)length;
            byte[] encryptedHeaderBytes = BuildEncryptedHeader(headerIv, key, footerOffset, padIv, padKey);
            using (FileStream fs = File.Open(filePath, FileMode.CreateNew, FileAccess.Write))
            {
                WriteHeader(fs, headerIv, encryptedHeaderBytes);
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
            return new EncryptedPad(new FileInfo(filePath), key, headerIv, padKey, padIv, footerOffset, rng);
        }

        public static EncryptedPad Load(FileInfo padFile, byte[] key, IPadDataGenerator rng)
        {
            byte[] headerIv;
            long footerOffset;
            byte[] padIv;
            byte[] padKey;
            using (FileStream fs = padFile.Open(FileMode.Open, FileAccess.Read))
            {
                headerIv = new byte[HeaderIvLength];
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
                footerOffset = BitConverter.ToInt64(encryptedHeader, 0);
                padIv = new byte[PadIvLength];
                Array.Copy(encryptedHeader, FooterOffsetLength, padIv, 0, padIv.Length);
                padKey = new byte[PadKeyLength];
                Array.Copy(encryptedHeader, FooterOffsetLength + padIv.Length, padKey, 0, padKey.Length);
            }
            return new EncryptedPad(padFile, key, headerIv, padKey, padIv, footerOffset, rng);
        }

        public EncryptedPad CopyTo(string newPadFilePath)
        {
            FileInfo copy = pad.CopyTo(newPadFilePath);
            return EncryptedPad.Load(copy, headerKey, rng);
        }

        public EncryptedPad CopyTo(DirectoryInfo newPadDir)
        {
            if (!newPadDir.Exists)
                newPadDir.Create();
            return CopyTo(Path.Combine(newPadDir.FullName, pad.Name));
        }

        public void UpdateEncryption(byte[] key)
        {
            UpdateEncryption(key, headerIv);
        }

        public void UpdateEncryption(byte[] key, IPadDataGenerator rng)
        {
            UpdateEncryption(key, rng.GetPadData(HeaderIvLength));
        }

        private void UpdateEncryption(byte[] key, byte[] iv)
        {
            headerIv = iv;
            headerKey = key;
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Write))
            {
                WriteHeader(fs);
            }
        }

        public FileInfo PadFileInfo {  get { return pad; } }

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
            WriteHeaderFooter();
            return bytes;
        }

        public override void UnsafeDelete()
        {
            pad.Delete();
        }

        private void WriteHeaderFooter()
        {
            headerIv = rng.GetPadData(HeaderIvLength);
            SimplifyChunkList();
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Write))
            {
                WriteHeader(fs);
                fs.Position = footerOffset;
                ulong headerOffset = HeaderLength;
                foreach (PadChunk chunk in usedChunks)
                {
                    byte[] chunkBytes = chunk.ToBytes();
                    chunkBytes = encryptor.EncryptBytesAtOffset(headerKey, headerIv, headerOffset, chunkBytes, true);
                    fs.Write(chunkBytes, 0, chunkBytes.Length);
                    headerOffset += (ulong)chunkBytes.Length;
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
                ulong chunkPosition = HeaderLength;
                int bytesRead = fs.Read(padChunkBuf, 0, padChunkBuf.Length);
                while (bytesRead > 0)
                {
                    if (bytesRead != PadChunk.BytesSize)
                        throw new InvalidEncryptedFileHeaderException("The footer has an incorrect size.");
                    padChunkBuf = encryptor.DecryptBytesAtOffset(headerKey, headerIv, chunkPosition, padChunkBuf, true);
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
                    string secondPad = "test2" + DefaultExt;
                    EncryptedPad pad2 = pad.CopyTo(secondPad);
                    try
                    {
                        byte[] key2 = rng.GetPadData(KeyLength);
                        pad2.UpdateEncryption(key2, rng.GetPadData(HeaderIvLength));
                        pad2 = null;
                        pad2 = EncryptedPad.Load(new FileInfo(secondPad), key2, rng);
                        testsSucceeded &= WriteTestResult("Key Update", !UtilityFunctions.ByteArraysEqual(key, key2));
                        testsSucceeded &= WriteTestResult("IV Update", !UtilityFunctions.ByteArraysEqual(pad.headerIv, pad2.headerIv));
                        foreach (ICryptoAlgorithmFactory factory in CryptoAlgorithmCache.Instance.Algorithms)
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

                                    FileInfo ctCopy = eCopy.CopyTo("test4.bin");
                                    try
                                    {
                                        EncryptedFile ptFile = EncryptedFile.CreateFromEncryptedFile(eCopy, pad);
                                        ptFile.Decrypt();
                                        testsSucceeded &= WriteTestResult(factory.Name + " Decryption", UtilityFunctions.FilesEqual(file, eCopy));

                                        EncryptedFile ptFile2 = EncryptedFile.CreateFromEncryptedFile(ctCopy, pad2);
                                        ptFile2.Decrypt();
                                        testsSucceeded &= WriteTestResult(factory.Name + " Pad Update Decryption", UtilityFunctions.FilesEqual(file, ctCopy));
                                    }
                                    finally
                                    {
                                        ctCopy.Delete();
                                    }
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
                    }
                    finally
                    {
                        pad2.UnsafeDelete();
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
