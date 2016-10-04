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

﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace LokeyLib
{
    public class MultiPad : AbstractPad
    {
        public const string DefaultExt = ".midx";

        public MultiPad(FileInfo index)
        {
            multipadIndex = index;
            ReadFromIndex();
        }

        public static MultiPad Create(DirectoryInfo dir, IPadDataGenerator rng, string name, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            return Create(dir, dir, rng, name, size, writeBlockSize);
        }

        public static MultiPad Create(DirectoryInfo midxDir, DirectoryInfo padsDir, IPadDataGenerator rng, string name, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            if (!midxDir.Exists)
                midxDir.Create();
            if (!padsDir.Exists)
                padsDir.Create();
            FileInfo midxFile = new FileInfo(Path.Combine(midxDir.FullName, name + DefaultExt));
            MultiPad mpad = Create(midxFile);
            if(mpad == null)
            {
                throw new CouldNotCreatePadException("Failed to create file \"" + midxFile.FullName + "\"");
            }
            if (size > 0)
            {
                ulong currentSize = 0;
                while (currentSize < size)
                {
                    ulong simplePadSizeToWrite = int.MaxValue > size - currentSize ? size - currentSize : int.MaxValue;
                    FileInfo sidxFile;
                    do {
                        sidxFile = new FileInfo(Path.Combine(padsDir.FullName, Path.GetRandomFileName().Replace(".", "") + SimplePadIndex.DefaultExt));
                    } while (sidxFile.Exists);
                    FileInfo spadFile;
                    do {
                        spadFile = new FileInfo(Path.Combine(padsDir.FullName, Path.GetRandomFileName().Replace(".", "") + SimplePad.DefaultExt));
                    } while (spadFile.Exists);
                    SimplePad simplePad = SimplePad.Create(spadFile, sidxFile, rng, simplePadSizeToWrite, writeBlockSize);
                    if (simplePad == null)
                    {
                        mpad.UnsafeDelete();
                        throw new CouldNotCreatePadException(
                            "SimplePad.Create(\"" + spadFile.FullName + "\", \""
                            + sidxFile.FullName + "\", "
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


        public static MultiPad Create(FileInfo index)
        {
            if (index.Exists) return null;
            using (FileStream fs = index.Create()) { }
            return new MultiPad(new FileInfo(index.FullName));
        }

        public override void UnsafeDelete()
        {
            foreach(SimplePad subpad in pads)
            {
                subpad.UnsafeDelete();
            }
            multipadIndex.Delete();
        }

        public MultiPad CopyTo(DirectoryInfo dir)
        {
            if (!dir.Exists)
                dir.Create();
            MultiPad newMPad = MultiPad.Create(new FileInfo(Path.Combine(dir.FullName, multipadIndex.Name)));
            foreach (SimplePad subpad in pads)
            {
                string relativeIdxPath = GetPathRelativeToIndex(subpad.IndexFileInfo.FullName);
                DirectoryInfo idxTgtDir = new FileInfo(Path.Combine(newMPad.multipadIndex.Directory.FullName, relativeIdxPath)).Directory;
                string relativePadPath = GetPathRelativeToIndex(subpad.PadFileInfo.FullName);
                DirectoryInfo padTgtDir = new FileInfo(Path.Combine(newMPad.multipadIndex.Directory.FullName, relativePadPath)).Directory;
                newMPad.AppendSubpad(subpad.CopyTo(idxTgtDir, padTgtDir));
            }
            return newMPad;
        }

        public override string Identifier { get { return multipadIndex.FullName; } }

        private List<SimplePad> pads = new List<SimplePad>();
        private FileInfo multipadIndex;

        public string IndexFilePath { get { return multipadIndex.FullName; } }

        private void AppendSubpad(SimplePad pad)
        {
            pads.Add(pad);
            WriteToIndex();
        }

        private void ReadFromIndex()
        {
            pads.Clear();
            using (FileStream fs = multipadIndex.Open(FileMode.Open, FileAccess.Read))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    string line = sr.ReadLine();
                    while (line != null)
                    {
                        if (!line.Equals(string.Empty))
                        {
                            string[] paths = line.Split(new char[] { '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
                            pads.Add(new SimplePad(new FileInfo(Path.GetFullPath(Path.Combine(multipadIndex.Directory.FullName, paths[0]))),
                                new FileInfo(Path.GetFullPath(Path.Combine(multipadIndex.Directory.FullName, paths[1])))));
                        }
                        line = sr.ReadLine();
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
                using (StreamWriter sw = new StreamWriter(fs, Encoding.UTF8))
                {
                    foreach(SimplePad pad in pads)
                    {
                        sw.Write(GetPathRelativeToIndex(pad.PadFileInfo.FullName));
                        sw.Write('\t');
                        sw.WriteLine(GetPathRelativeToIndex(pad.IndexFileInfo.FullName));
                    }
                }
            }
        }

        public override bool IsValid
        {
            get
            {
                return multipadIndex.Exists && pads.All(pad => IsValid);
            }
        }

        public override ulong PadSize
        {
            get
            {
                return pads.Aggregate(0UL, (runningSum, pad) => pad.PadSize + runningSum);
            }
        }

        public override IEnumerable<PadChunk> UnusedChunks
        {
            get
            {
                // Generates the list of unused pad chunks by creating Tuples 
                // of pads with the sum of the sizes of the pads preceding them
                // in the MultiPad, then selecting all of the 
                List<Tuple<SimplePad, UInt64>> padsWithStartOffsets = new List<Tuple<SimplePad, ulong>>(pads.Count);
                UInt64 startOffset = 0UL;
                foreach(SimplePad pad in pads)
                {
                    padsWithStartOffsets.Add(new Tuple<SimplePad, ulong>(pad, startOffset));
                    startOffset += pad.PadSize;
                }
                return padsWithStartOffsets.SelectMany(
                    tup => tup.Item1.UnusedChunks.Select(
                        chunk => new PadChunk(chunk.Start + tup.Item2, chunk.Size)
                    )
                ).Simplify();
            }
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
                for(int i = padInfoAtStart.Item1 + 1; (size - bytesFromPad) > 0; ++i)
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
        private const string ClassName = "MultiPad";

        public static bool RunTest()
        {
            MultiPad pad = null;
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            try
            {
                bool testsSucceeded = true;
                const ulong simplePadSize = 4096 + 1024;
                const ulong multiPadSize = simplePadSize * 3;
                IPadDataGenerator rng = CryptoAlgorithmCache.Instance.RNGs.First();
                string midxFileName = "Test" + DefaultExt;
                pad = MultiPad.Create(new FileInfo(midxFileName));
                testsSucceeded &= WriteTestResult("Initial Pad Size", pad.PadSize == 0UL);
                PadChunk[] chunks = pad.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Initial Pad Chunks", chunks.Length == 0);

                SimplePad spad1 = SimplePad.Create(new FileInfo("Test1" + SimplePad.DefaultExt), new FileInfo("Test1" + SimplePadIndex.DefaultExt), rng, simplePadSize);
                pad.AppendSubpad(spad1);
                SimplePad spad2 = SimplePad.Create(new FileInfo("Test2" + SimplePad.DefaultExt), new FileInfo("Test2" + SimplePadIndex.DefaultExt), rng, simplePadSize);
                pad.AppendSubpad(spad2);
                SimplePad spad3 = SimplePad.Create(new FileInfo("Test3" + SimplePad.DefaultExt), new FileInfo("Test3" + SimplePadIndex.DefaultExt), rng, simplePadSize);
                pad.AppendSubpad(spad3);
                testsSucceeded &= WriteTestResult("Appended Pad Size", pad.PadSize == multiPadSize);

                /*byte[] chunk1 =*/ pad.GetPadBytes(simplePadSize - 1024, 2048);
                chunks = pad.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Spanning Chunk", chunks.Length == 2 
                    && chunks[0].Start == 0 && chunks[0].Size == 4096
                    && chunks[1].Start == 4096 + 2048 && chunks[1].Size == simplePadSize + simplePadSize - 1024);
                chunks = spad1.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 1 Chunk", chunks.Length == 1 && chunks[0].Start == 0 && chunks[0].Size == simplePadSize - 1024);
                chunks = spad2.UnusedChunks.ToArray();
                testsSucceeded &= WriteTestResult("Subpad 2 Chunk", chunks.Length == 1 && chunks[0].Start == 1024 && chunks[0].Size == simplePadSize - 1024);

                /*byte[] chunk2 =*/ pad.GetPadBytes(simplePadSize + simplePadSize - 512, 512);
                /*byte[] chunk3 =*/ pad.GetPadBytes(simplePadSize + simplePadSize, 512);
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
            catch(Exception e)
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
