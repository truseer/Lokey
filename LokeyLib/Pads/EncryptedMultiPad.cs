/***********************************************************************/
// LokeyLib - A library for the management and use of cryptographic pads
/***********************************************************************/
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
/***********************************************************************/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LokeyLib
{
    public class EncryptedMultiPad : AbstractPad, IEncryptionPadObject
    {
        public const string DefaultExt = ".eidx";

        public EncryptedMultiPad(FileInfo index, byte[] key, IPadDataGenerator rng)
        {
            multipadIndex = index;
            this.key = key;
            ReadFromIndex(rng);
        }

        public static EncryptedMultiPad Create(DirectoryInfo dir, byte[] key, IPadDataGenerator rng, string name, ulong size, int writeBlockSize = 4096)
        {
            return Create(dir, dir, key, rng, name, size, writeBlockSize);
        }

        public static EncryptedMultiPad Create(DirectoryInfo midxDir, DirectoryInfo padsDir, byte[] key, IPadDataGenerator rng, string name, ulong size, int writeBlockSize = 4096)
        {
            if (!midxDir.Exists)
                midxDir.Create();
            if (!midxDir.FullName.Equals(padsDir.FullName) && !padsDir.Exists)
                padsDir.Create();
            FileInfo midxFile = new FileInfo(Path.Combine(midxDir.FullName, name + DefaultExt));
            EncryptedMultiPad mpad = Create(midxFile, key, rng);
            if (mpad == null)
            {
                throw new CouldNotCreatePadException("Failed to create file \"" + midxFile.FullName + "\"");
            }
            if (size > 0)
            {
                ulong currentSize = 0;
                while (currentSize < size)
                {
                    ulong simplePadSizeToWrite = int.MaxValue > size - currentSize ? size - currentSize : int.MaxValue;
                    string spadFile;
                    do
                    {
                        spadFile = Path.Combine(padsDir.FullName, Path.GetRandomFileName().Replace(".", "") + EncryptedPad.DefaultExt);
                    } while (File.Exists(spadFile));
                    EncryptedPad simplePad = EncryptedPad.Create(spadFile, key, rng, simplePadSizeToWrite, writeBlockSize);
                    if (simplePad == null)
                    {
                        mpad.NonsecureDelete();
                        throw new CouldNotCreatePadException(
                            "EncryptedPad.Create(\"" + spadFile + "\", \""
                            + rng.ToString() + ", "
                            + simplePadSizeToWrite.ToString() + ", "
                            + writeBlockSize.ToString() + ") failed.");
                    }
                    mpad.AppendSubpad(simplePad);
                    currentSize += simplePadSizeToWrite;
                }
            }
            return mpad;
        }
        
        public static EncryptedMultiPad Create(FileInfo index, byte[] key, IPadDataGenerator rng)
        {
            if (index.Exists)
                throw new CouldNotCreatePadException("\"" + index.FullName + "\" already exists.");
            using (FileStream fs = index.Create())
            {
                byte[] iv = rng.GetPadData(Aes256Ctr.IvSizeBytes);
                fs.Write(iv, 0, iv.Length);
            }
            return new EncryptedMultiPad(new FileInfo(index.FullName), key, rng);
        }

        private void UpdateIndexEncryption(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
            WriteToIndex();
        }

        public void UpdateEncryption(byte[] key)
        {
            UpdateIndexEncryption(key, iv);
            foreach (EncryptedPad subpad in pads)
            {
                subpad.UpdateEncryption(key);
            }
        }

        public void UpdateEncryption(byte[] key, IPadDataGenerator rng)
        {
            UpdateIndexEncryption(key, rng.GetPadData(Aes256Ctr.IvSizeBytes));
            foreach (EncryptedPad subpad in pads)
            {
                subpad.UpdateEncryption(key, rng);
            }
        }

        public EncryptedMultiPad CopyTo(DirectoryInfo dir, IPadDataGenerator rng)
        {
            if (!dir.Exists)
                dir.Create();
            EncryptedMultiPad newMPad = Create(new FileInfo(Path.Combine(dir.FullName, multipadIndex.Name)), key, rng);
            foreach (EncryptedPad subpad in pads)
            {
                string relativePadPath = GetPathRelativeToIndex(subpad.PadFileInfo.FullName);
                DirectoryInfo padTgtDir = new FileInfo(Path.Combine(newMPad.multipadIndex.Directory.FullName, relativePadPath)).Directory;
                newMPad.AppendSubpad(subpad.CopyTo(padTgtDir));
            }
            return newMPad;
        }

        public override string Identifier { get { return multipadIndex.FullName; } }

        private List<EncryptedPad> pads = new List<EncryptedPad>();
        private FileInfo multipadIndex;
        private byte[] key;
        private byte[] iv;

        public string IndexFilePath { get { return multipadIndex.FullName; } }

        private void AppendSubpad(EncryptedPad pad)
        {
            pads.Add(pad);
            WriteToIndex();
        }

        private void ReadFromIndex(IPadDataGenerator rng)
        {
            pads.Clear();
            using (FileStream fs = multipadIndex.Open(FileMode.Open, FileAccess.Read))
            {
                if (iv == null)
                    iv = new byte[Aes256Ctr.IvSizeBytes];
                int bytesRead = fs.Read(iv, 0, iv.Length);
                if (bytesRead < iv.Length)
                    throw new InvalidEncryptedFileHeaderException("Header from \"" + multipadIndex.FullName + "\" could not be read.");
                byte[] indexBuffer = new byte[multipadIndex.Length - iv.Length];
                bytesRead = fs.Read(indexBuffer, 0, indexBuffer.Length);
                if (bytesRead < indexBuffer.Length)
                    throw new CouldNotCreatePadException("Could not read all of pad index\"" + multipadIndex.FullName + "\".");
                indexBuffer = new Aes256Ctr().DecryptBytes(key, iv, indexBuffer, true);
                using (MemoryStream ms = new MemoryStream(indexBuffer))
                {
                    using (StreamReader sr = new StreamReader(ms, Encoding.UTF8))
                    {
                        string line = sr.ReadLine();
                        while (line != null)
                        {
                            if (!line.Equals(string.Empty))
                            {
                                pads.Add(EncryptedPad.Load(new FileInfo(Path.GetFullPath(Path.Combine(multipadIndex.Directory.FullName, line))), key, rng));
                            }
                            line = sr.ReadLine();
                        }
                    }
                }
            }
        }

        private string GetPathRelativeToIndex(string path)
        {
            return UtilityFunctions.GetRelativePath(multipadIndex.FullName, path);
        }

        private void WriteToIndex()
        {
            using (FileStream fs = multipadIndex.Open(FileMode.Create, FileAccess.Write))
            {
                fs.Write(iv, 0, iv.Length);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (StreamWriter sw = new StreamWriter(ms, Encoding.UTF8))
                    {
                        foreach (EncryptedPad pad in pads)
                        {
                            sw.WriteLine(GetPathRelativeToIndex(pad.PadFileInfo.FullName));
                        }
                        byte[] buffer = ms.GetBuffer();
                        buffer = new Aes256Ctr().EncryptBytes(key, iv, buffer, true);
                        fs.Write(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        public override bool IsValid { get { return multipadIndex.Exists && pads.All(pad => IsValid); } }

        public override ulong PadSize { get { return pads.Aggregate(0UL, (runningSum, pad) => pad.PadSize + runningSum); } }

        public override IEnumerable<PadChunk> UnusedChunks
        {
            get
            {
                // Generates the list of unused pad chunks by creating Tuples 
                // of pads with the sum of the sizes of the pads preceding them
                // in the EncryptedMultiPad, then selecting all of the 
                List<Tuple<EncryptedPad, UInt64>> padsWithStartOffsets = new List<Tuple<EncryptedPad, ulong>>(pads.Count);
                UInt64 startOffset = 0UL;
                foreach (EncryptedPad pad in pads)
                {
                    padsWithStartOffsets.Add(new Tuple<EncryptedPad, ulong>(pad, startOffset));
                    startOffset += pad.PadSize;
                }
                return padsWithStartOffsets.SelectMany(
                    tup => tup.Item1.UnusedChunks.Select(
                        chunk => new PadChunk(chunk.Start + tup.Item2, chunk.Size)
                    )
                ).Simplify();
            }
        }

        public override IEnumerable<FileInfo> ComponentFiles
        {
            get { return pads.SelectMany(pad => pad.ComponentFiles).Concat(new FileInfo[] { multipadIndex }); }
        }

        private Tuple<int, UInt64> GetPadIndexAndPadStartOffsetAtMultipadByteOffset(UInt64 targetOffset)
        {
            UInt64 startOffset = 0UL;
            for (int i = 0; i < pads.Count; ++i)
            {
                UInt64 padSize = pads[i].PadSize;
                if (startOffset + padSize > targetOffset)
                    return new Tuple<int, ulong>(i, startOffset);
                startOffset += padSize;
            }
            return null;
        }

        public override byte[] GetPadBytes(ulong start, ulong size)
        {
            if (UInt64.MaxValue - size < start)
                throw new InvalidChunkException("Chunk end exceeds UInt64.MaxValue.");
            if (size + start > PadSize)
                throw new InvalidChunkException("Chunk end exceeds pad size.");
            // The index and the offset of the beginning of the subpad containing the specified start
            Tuple<int, UInt64> padInfoAtStart = GetPadIndexAndPadStartOffsetAtMultipadByteOffset(start);
            // The offset from the start of the subpad of the specified start
            UInt64 startPadOffset = start - padInfoAtStart.Item2;
            // The size of the pad containing the specified start
            UInt64 thisPadSize = pads[padInfoAtStart.Item1].PadSize;
            UInt64 bytesFromPad = thisPadSize - startPadOffset;
            if (bytesFromPad >= size)
            {
                return pads[padInfoAtStart.Item1].GetPadBytes(startPadOffset, size);
            }
            else
            {
                byte[] bytes = new byte[size];
                byte[] partialBytes = pads[padInfoAtStart.Item1].GetPadBytes(startPadOffset, bytesFromPad);
                Array.Copy(partialBytes, bytes, partialBytes.LongLength);
                for (int i = padInfoAtStart.Item1 + 1; (size - bytesFromPad) > 0; ++i)
                {
                    thisPadSize = pads[i].PadSize;
                    UInt64 bytesToGetFromPad = ((size - bytesFromPad) > thisPadSize) ? thisPadSize : (size - bytesFromPad);
                    partialBytes = pads[i].GetPadBytes(0, bytesToGetFromPad);
                    Array.Copy(partialBytes, 0, bytes, (long)bytesFromPad, partialBytes.LongLength);
                    bytesFromPad += bytesToGetFromPad;
                }
                return bytes;
            }
        }

#if DEBUG
        private const string ClassName = "EncryptedMultiPad";

        public static bool RunTest()
        {
            EncryptedMultiPad pad = null;
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            try
            {
                bool testsSucceeded = true;
                const ulong simplePadSize = 4096 + 1024;
                const ulong multiPadSize = simplePadSize * 3;
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.RNGs.First();
                string midxFileName = "Test" + DefaultExt;
                byte[] key = rng.GetPadData(EncryptedPad.KeyLength);
                pad = EncryptedMultiPad.Create(new FileInfo(midxFileName), key, rng);
                testsSucceeded &= WriteTestResult("Initial Pad Size", pad.PadSize == 0UL);
                PadChunk[] chunks = pad.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Initial Pad Chunks", chunks.Length == 0);
                
                EncryptedPad spad1 = EncryptedPad.Create("Test1" + EncryptedPad.DefaultExt, key, rng, simplePadSize);
                pad.AppendSubpad(spad1);
                EncryptedPad spad2 = EncryptedPad.Create("Test2" + EncryptedPad.DefaultExt, key, rng, simplePadSize);
                pad.AppendSubpad(spad2);
                EncryptedPad spad3 = EncryptedPad.Create("Test3" + EncryptedPad.DefaultExt, key, rng, simplePadSize);
                pad.AppendSubpad(spad3);
                testsSucceeded &= WriteTestResult("Appended Pad Size", pad.PadSize == multiPadSize);

                /*byte[] chunk1 =*/
                pad.GetPadBytes(simplePadSize - 1024, 2048);
                chunks = pad.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Spanning Chunk", chunks.Length == 2
                    && chunks[0].Start == 0 && chunks[0].Size == 4096
                    && chunks[1].Start == 4096 + 2048 && chunks[1].Size == simplePadSize + simplePadSize - 1024);
                chunks = spad1.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 1 Chunk", chunks.Length == 1 && chunks[0].Start == 0 && chunks[0].Size == simplePadSize - 1024);
                chunks = spad2.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 2 Chunk", chunks.Length == 1 && chunks[0].Start == 1024 && chunks[0].Size == simplePadSize - 1024);

                /*byte[] chunk2 =*/
                pad.GetPadBytes(simplePadSize + simplePadSize - 512, 512);
                /*byte[] chunk3 =*/
                pad.GetPadBytes(simplePadSize + simplePadSize, 512);
                chunks = pad.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Adjoining Chunk", chunks.Length == 3
                    && chunks[0].Start == 0 && chunks[0].Size == 4096
                    && chunks[1].Start == 4096 + 2048 && chunks[1].Size == simplePadSize - (512 + 1024)
                    && chunks[2].Start == simplePadSize + simplePadSize + 512 && chunks[2].Size == simplePadSize - 512);
                chunks = spad2.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 2 Chunk", chunks.Length == 1 && chunks[0].Start == 1024 && chunks[0].Size == simplePadSize - (1024 + 512));
                chunks = spad3.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 3 Chunk", chunks.Length == 1 && chunks[0].Start == 512 && chunks[0].Size == simplePadSize - 512);

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
