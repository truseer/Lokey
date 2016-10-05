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

using System;
using System.IO;
using System.Text;

namespace LokeyLib
{
    public class EncryptedFile
    {
        public const int DefaultEncryptedFileBlockSize = 4096;

        public const string FileNamePackedExt = ".nmls";

        public class EncryptedFileHeader
        {
            public UInt64 HeaderKeyLocation { get; }
            public ICryptoAlgorithm Algorithm { get; }
            public PadChunk FileKeyLocation { get; }

            static private Aes256CtrPadIvAlgorithm headerEncryptionAlgorithm = new Aes256CtrPadIvAlgorithm();

            public const uint StaticEncryptedBytesSize = sizeof(uint) + PadChunk.BytesSize + sizeof(uint);
            public const uint UnencryptedBytesSize = sizeof(UInt64);
            public uint BytesSize { get { return UnencryptedBytesSize + EncryptedBytesSize; } }
            public uint EncryptedBytesSize { get { return StaticEncryptedBytesSize + Algorithm.HeaderSize; } }
            public PadChunk HeaderKeyChunk { get { return new PadChunk(HeaderKeyLocation, EncryptedBytesSize); } }

            /******************************************************************
            | Header prepended to the encrypted file.                         |
            *******************************************************************
            | Description                    | Size (Bytes)      | Encryption |
            *******************************************************************
            | Header Key Location            | 8                 | None       |
            | Algorithm UID                  | 4                 | AES256CTR  |
            | File Key Chunk                 | 16                | AES256CTR  |
            | Algorithm Specific Header Size | 4                 | AES256CTR  |
            | Algorithm Specific Header      | Algorithm Defined | AES256CTR  |
            ******************************************************************/

            public static EncryptedFileHeader Generate(UInt64 headerKeyLocation,
                ICryptoAlgorithmFactory algorithmFactory, PadChunk fileKeyLocation)
            {
                return new EncryptedFileHeader(headerKeyLocation, algorithmFactory.GenerateCryptoAlgorithm(), fileKeyLocation);
            }

            public static EncryptedFileHeader Generate(AbstractPad pad, ICryptoAlgorithmFactory algorithmFactory, UInt64 fileSize)
            {
                ICryptoAlgorithm algorithm = algorithmFactory.GenerateCryptoAlgorithm();
                UInt64 fileKeySize = algorithm.GetKeySize(fileSize);
                ulong headerKeySize = headerEncryptionAlgorithm.GetKeySize(StaticEncryptedBytesSize + algorithm.HeaderSize);
                PadChunk fileChunk = null, headerChunk = null;
                foreach (PadChunk ichunk in pad.UnusedChunks)
                {
                    PadChunk chunk = ichunk;
                    if (headerChunk == null)
                    {
                        if (chunk.Size >= headerKeySize)
                        {
                            headerChunk = new PadChunk(chunk.Start, headerKeySize);
                            chunk = new PadChunk(chunk.Start + headerKeySize, chunk.Size - headerKeySize);
                        }
                    }
                    if (fileChunk == null)
                    {
                        if (chunk.Size >= fileKeySize)
                        {
                            fileChunk = new PadChunk(chunk.Start + (chunk.Size - fileKeySize), fileKeySize);
                        }
                    }
                    if (headerChunk != null && fileChunk != null)
                    {
                        return new EncryptedFileHeader(headerChunk.Start, algorithm, fileChunk);
                    }
                }
                throw new InsufficientPadException("Insufficient pad for file encryption.");
            }

            public static EncryptedFileHeader FromFile(AbstractPad pad, FileInfo file)
            {
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.Read))
                {
                    byte[] headerUnencryptedBytes = new byte[UnencryptedBytesSize];
                    int bytesRead = fs.Read(headerUnencryptedBytes, 0, headerUnencryptedBytes.Length);
                    if (bytesRead == UnencryptedBytesSize)
                    {
                        long encryptedHeaderPosition = fs.Position;
                        byte[] headerEncryptedBytes = new byte[StaticEncryptedBytesSize];
                        bytesRead = fs.Read(headerEncryptedBytes, 0, headerEncryptedBytes.Length);
                        if (bytesRead == headerEncryptedBytes.Length)
                        {
                            UInt64 headerKeyLocation = BitConverter.ToUInt64(headerUnencryptedBytes, 0);
                            PadChunk headerKeyChunk = GenerateHeaderKeyChunk(headerKeyLocation);
                            headerEncryptedBytes = headerEncryptionAlgorithm.Decrypt(pad, headerKeyChunk, headerEncryptedBytes);
                            UInt32 uid = BitConverter.ToUInt32(headerEncryptedBytes, 0);
                            PadChunk fileKeyLocation = PadChunk.FromBytes(headerEncryptedBytes, sizeof(UInt32));
                            UInt32 specificHeaderSize = BitConverter.ToUInt32(headerEncryptedBytes, sizeof(Int32) + PadChunk.BytesSize);
                            byte[] algorithmSpecificHeader = new byte[specificHeaderSize];
                            if (specificHeaderSize > 0)
                            {
                                headerEncryptedBytes = new byte[specificHeaderSize + StaticEncryptedBytesSize];
                                fs.Seek(encryptedHeaderPosition, SeekOrigin.Begin);
                                bytesRead = fs.Read(headerEncryptedBytes, 0, headerEncryptedBytes.Length);
                                if (bytesRead == headerEncryptedBytes.Length)
                                {
                                    headerEncryptedBytes = headerEncryptionAlgorithm.Decrypt(pad, headerKeyChunk, headerEncryptedBytes);
                                    Array.Copy(headerEncryptedBytes, StaticEncryptedBytesSize, algorithmSpecificHeader, 0, algorithmSpecificHeader.Length);
                                }
                                else
                                {
                                    throw new InvalidEncryptedFileHeaderException("Algorithm-specific header could not be read.");
                                }
                            }
                            ICryptoAlgorithm algorithm =
                                CryptoAlgorithmCache.Instance.GetAlgorithm(uid).GenerateCryptoAlgorithm(algorithmSpecificHeader);
                            return new EncryptedFileHeader(headerKeyLocation, algorithm, fileKeyLocation);
                        }
                    }
                    throw new InvalidEncryptedFileHeaderException("Header could not be read.");
                }
            }

            public byte[] ToBytes(AbstractPad pad)
            {
                byte[] bytes = new byte[BytesSize];
                
                // Unencrypted elements bytes
                byte[] elementBytes = BitConverter.GetBytes(HeaderKeyLocation);
                Array.Copy(elementBytes, bytes, sizeof(UInt64));

                // Encrypted elements bytes
                byte[] encryptedBytes = new byte[EncryptedBytesSize];
                elementBytes = BitConverter.GetBytes(Algorithm.UID);
                Array.Copy(elementBytes, encryptedBytes, sizeof(UInt32));
                elementBytes = FileKeyLocation.ToBytes();
                Array.Copy(elementBytes, 0, encryptedBytes, sizeof(UInt32), PadChunk.BytesSize);
                elementBytes = BitConverter.GetBytes(Algorithm.HeaderSize);
                Array.Copy(elementBytes, 0, encryptedBytes, sizeof(UInt32) + PadChunk.BytesSize, sizeof(UInt32));
                // Algorithm-specific header
                Array.Copy(Algorithm.Header, 0, encryptedBytes, StaticEncryptedBytesSize, Algorithm.HeaderSize);
                
                // Encrypt the encrypted header bytes and copy it to the output buffer
                encryptedBytes = headerEncryptionAlgorithm.Encrypt(pad, HeaderKeyChunk, encryptedBytes);
                Array.Copy(encryptedBytes, 0, bytes, UnencryptedBytesSize, EncryptedBytesSize);
                return bytes;
            }

            public bool IsValidForPad(AbstractPad pad)
            {
                PadChunk headerKeyChunk = HeaderKeyChunk;
                if (headerKeyChunk.Overlap(FileKeyLocation)) return false;
                UInt64 padSize = pad.PadSize;
                return headerKeyChunk.End < padSize
                    && FileKeyLocation.End < padSize;
            }

            private EncryptedFileHeader(UInt64 headerKeyLocation, ICryptoAlgorithm algorithm, PadChunk algorithmKeyLocation)
            {
                HeaderKeyLocation = headerKeyLocation;
                Algorithm = algorithm;
                FileKeyLocation = algorithmKeyLocation;
            }

            private static PadChunk GenerateHeaderKeyChunk(UInt64 headerKeyLocation)
            {
                return new PadChunk(headerKeyLocation, headerEncryptionAlgorithm.GetKeySize(ulong.MaxValue));
            }
        }

        private EncryptedFile(FileInfo file, AbstractPad pad, EncryptedFileHeader header, bool isEncrypted)
        {
            this.file = file;
            this.pad = pad;
            this.header = header;
            IsEncrypted = isEncrypted;
            FileNameIsPacked = file.Extension.Equals(FileNamePackedExt);
        }

        public static EncryptedFile CreateFromEncryptedFile(FileInfo file, IPadConnection connection)
        {
            return CreateFromEncryptedFile(file, connection.From);
        }

        public static EncryptedFile CreateFromEncryptedFile(FileInfo file, AbstractPad pad)
        {
            return new EncryptedFile(file, pad, EncryptedFileHeader.FromFile(pad, file), true);
        }

        public static EncryptedFile CreateFromPlaintextFile(FileInfo file, IPadConnection connection,
            ICryptoAlgorithmFactory algorithm)
        {
            return CreateFromPlaintextFile(file, connection.To, algorithm);
        }

        public static EncryptedFile CreateFromPlaintextFile(FileInfo file, AbstractPad pad,
            ICryptoAlgorithmFactory algorithm)
        {
            return new EncryptedFile(file, pad, EncryptedFileHeader.Generate(pad, algorithm, (ulong)file.Length), false);
        }

        public static EncryptedFile CreateFromPlaintextFile(FileInfo file, IPadConnection connection,
            ICryptoAlgorithmFactory algorithm, UInt64 headerKeyLocation, PadChunk algorithmKey)
        {
            return CreateFromPlaintextFile(file, connection.To, algorithm, headerKeyLocation, algorithmKey);
        }

        public static EncryptedFile CreateFromPlaintextFile(FileInfo file, AbstractPad pad,
            ICryptoAlgorithmFactory algorithm, UInt64 headerKeyLocation, PadChunk algorithmKey)
        {
            return new EncryptedFile(file, pad, EncryptedFileHeader.Generate(headerKeyLocation, algorithm, algorithmKey), false);
        }

        private FileInfo file;
        private EncryptedFileHeader header;
        private AbstractPad pad;

        public bool IsEncrypted { get; private set; }
        public bool FileNameIsPacked { get; private set; }
        public string FilePath {  get { return file.FullName; } }
        
        /************************************************
        | Footer appended to the encrypted file.        |
        *************************************************
        | Description                    | Size (Bytes) |
        *************************************************
        | File Name String               | N            |
        | File Name Start Location       | 8            |
        ************************************************/

        public void PackFileName()
        {
            if(!FileNameIsPacked)
            {
                using (FileStream fs = file.Open(FileMode.Append, FileAccess.Write))
                {
                    long position = fs.Position;
                    byte[] fileNameBytes = Encoding.UTF8.GetBytes(file.Name);
                    byte[] positonBytes = BitConverter.GetBytes(position);
                    fs.Write(fileNameBytes, 0, fileNameBytes.Length);
                    fs.Write(positonBytes, 0, positonBytes.Length);
                }
                FileInfo fi = new FileInfo(file.FullName);
                string newPath = Path.Combine(fi.DirectoryName, Path.GetRandomFileName().Replace(".", "") + FileNamePackedExt);
                fi.MoveTo(newPath);
                file = new FileInfo(newPath);
            }
        }

        public void UnpackFileName()
        {
            if(FileNameIsPacked)
            {
                string fileName = null;
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.ReadWrite))
                {
                    byte[] stringPositionBytes = new byte[sizeof(long)];
                    fs.Seek(-sizeof(long), SeekOrigin.End);
                    int bytesRead = fs.Read(stringPositionBytes, 0, stringPositionBytes.Length);
                    if(bytesRead == stringPositionBytes.Length)
                    {
                        long stringPosition = BitConverter.ToInt64(stringPositionBytes, 0);
                        fs.Position = stringPosition;
                        long stringBufferLength = (fs.Length - stringPosition) - sizeof(long);
                        byte[] stringBuffer = new byte[stringBufferLength];
                        int fileNameBytesRead = fs.Read(stringBuffer, 0, stringBuffer.Length);
                        if (fileNameBytesRead == stringBufferLength)
                        {
                            fileName = Encoding.UTF8.GetString(stringBuffer);
                            fs.SetLength(stringPosition);
                        }
                    }
                }
                if (fileName != null)
                {
                    FileInfo fi = new FileInfo(file.FullName);
                    string newPath = Path.Combine(file.DirectoryName, fileName);
                    fi.MoveTo(newPath);
                    file = new FileInfo(newPath);
                    FileNameIsPacked = false;
                }
            }
        }

        public void Decrypt(int blockSize = DefaultEncryptedFileBlockSize)
        {
            if (IsEncrypted)
            {
                int modBlockSize = blockSize % header.Algorithm.BlockSize;
                if (modBlockSize != 0)
                    blockSize += header.Algorithm.BlockSize - modBlockSize;
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.ReadWrite))
                {
                    long position = 0L;
                    foreach (byte[] block in header.Algorithm.Decrypt(pad, header.FileKeyLocation,
                        new FileBlockEnumerable(fs, blockSize, header.BytesSize)))
                    {
                        fs.Seek(position, SeekOrigin.Begin);
                        fs.Write(block, 0, block.Length);
                        position = fs.Position;
                    }
                    fs.SetLength(position);
                }
                IsEncrypted = false;
                UnpackFileName();
            }
        }

        public void Encrypt(int blockSize = DefaultEncryptedFileBlockSize)
        {
            if (!IsEncrypted)
            {
                PackFileName();
                // block size must be larger than the header in order to ensure that
                // none of the file is lost when the header is written
                if (blockSize < header.BytesSize)
                    blockSize = (int)header.BytesSize;
                int modBlockSize = blockSize % header.Algorithm.BlockSize;
                if (modBlockSize != 0)
                    blockSize += header.Algorithm.BlockSize - modBlockSize;
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.ReadWrite))
                {
                    // have to construct this first because it caches the first block
                    // so that the header can be written over it
                    BufferedEnumerable<byte[]> fileBlocks = new BufferedEnumerable<byte[]>(1, new FileBlockEnumerable(fs, blockSize, 0));
                    byte[] headerBytes = header.ToBytes(pad);
                    fs.Position = 0L;
                    fs.Write(headerBytes, 0, headerBytes.Length);
                    long position = fs.Position;
                    foreach (byte[] block in header.Algorithm.Encrypt(pad, header.FileKeyLocation, fileBlocks))
                    {
                        fs.Position = position;
                        fs.Write(block, 0, block.Length);
                        position = fs.Position;
                    }
                    fs.SetLength(position);
                }
                IsEncrypted = true;
            }
        }

#if DEBUG
        private const string ClassName = "EncryptedFile";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            SimplePad pad = null;
            try
            {
                bool testsSucceeded = true;
                pad = SimplePad.Create(new FileInfo("test.pad"), new FileInfo("test.idx"), CryptoAlgorithmCache.Instance.GetRNG(1), 1 << 22);
                FileInfo ptTest = UtilityFunctions.GenerateTestPlaintextFile("test.bin", 1 << 21);
                try
                {
                    foreach (ICryptoAlgorithmFactory cf in CryptoAlgorithmCache.Instance.Algorithms)
                    {
                        FileInfo fileCopy = ptTest.CopyTo("testcopy.bin");
                        try
                        {
                            EncryptedFile pt = EncryptedFile.CreateFromPlaintextFile(fileCopy, pad, cf);
                            pt.Encrypt();
                            fileCopy = new FileInfo(fileCopy.FullName);
                            FileInfo ciphertextCopy = fileCopy.CopyTo("testcopy.bin.ct");
                            try
                            {
                                EncryptedFile ct = EncryptedFile.CreateFromEncryptedFile(ciphertextCopy, pad);
                                ct.Decrypt();
                                ciphertextCopy = new FileInfo(ciphertextCopy.FullName);
                                testsSucceeded &= WriteTestResult(cf.Name + " File Encryption/Decryption", UtilityFunctions.FilesEqual(ptTest, ciphertextCopy));
                            }
                            finally { ciphertextCopy.Delete(); }
                        }
                        finally { fileCopy.Delete(); }
                    }
                    return testsSucceeded;
                }
                finally { ptTest.Delete(); }
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
