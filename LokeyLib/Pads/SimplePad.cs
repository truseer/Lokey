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

namespace LokeyLib
{
    public class SimplePad : AbstractPad
    {
        public const string DefaultExt = ".spad";

        public class PadIncompleteReadException : Exception
        {
            public PadIncompleteReadException(string message) : base(message) { }
            public PadIncompleteReadException() : base("Failed to read the entire requested chunk, though pad should be large enough.") { }
        }

        public SimplePad(FileInfo pad, FileInfo index)
        {
            this.pad = pad;
            this.index = new SimplePadIndex(index);
        }

        private SimplePad(FileInfo pad, SimplePadIndex index)
        {
            this.pad = pad;
            this.index = index;
        }

        // Creates an empty SimplePad
        public static SimplePad Create(FileInfo pad, FileInfo index)
        {
            if (pad.Exists) return null;
            SimplePadIndex idx = SimplePadIndex.Create(index);
            if (idx == null) return null;
            using (FileStream fs = pad.Create()) { }
            pad = new FileInfo(pad.FullName);
            return pad.Exists ? new SimplePad(pad, idx) : null;
        }

        // Creates a SimplePad filling it with padSize bytes from generator
        public static SimplePad Create(FileInfo pad, FileInfo index, 
            IPadDataGenerator generator, UInt64 padSize, int writeChunkSize = DefaultWriteBlockSize)
        {
            SimplePad newPad = Create(pad, index);
            if(newPad != null)
            {
                newPad.AppendBytes(generator, padSize, writeChunkSize);
            }
            return newPad;
        }

        public override void UnsafeDelete()
        {
            pad.Delete();
            index.UnsafeDelete();
        }

        public SimplePad CopyTo(DirectoryInfo dir)
        {
            return CopyTo(dir, dir);
        }

        public SimplePad CopyTo(DirectoryInfo newIdxDir, DirectoryInfo newPadDir)
        {
            SimplePadIndex newIdx = index.CopyTo(newIdxDir);
            try {
                if (!newPadDir.Exists)
                    newPadDir.Create();
                FileInfo newPad = pad.CopyTo(Path.Combine(newPadDir.FullName, pad.Name));
                return new SimplePad(newPad, newIdx);
            }
            catch
            {
                newIdx.UnsafeDelete();
                throw;
            }
        }

        private FileInfo pad;
        private SimplePadIndex index;

        public FileInfo IndexFileInfo { get { return index.IndexFileInfo; } }
        public FileInfo PadFileInfo { get { return pad; } }

        public override string Identifier { get { return index.IndexFileInfo.FullName + ";" + pad.FullName; } }

        public override bool IsValid
        {
            get
            {
                return pad.Exists && index.IsValid;
            }
        }

        public override UInt64 PadSize
        {
            get
            {
                long length = pad.Length;
                if (length < 0)
                    throw new IOException();
                else
                    return (UInt64)length;
            }
        }

        public override IEnumerable<PadChunk> UnusedChunks
        {
            get { return index.GenerateUnusedChunks(PadSize); }
        }

        public override IEnumerable<FileInfo> ComponentFiles
        {
            get { return index.ComponentFiles.Concat(new FileInfo[] { pad }); }
        }

        public const int DefaultWriteBlockSize = 2048;

        public void AppendBytes(IPadDataGenerator generator, UInt64 numBytes, int writeBlockSize = DefaultWriteBlockSize)
        {
            if (writeBlockSize <= 0)
                writeBlockSize = DefaultWriteBlockSize;
            using (FileStream fs = pad.Open(FileMode.Append, FileAccess.Write))
            {
                UInt64 bytesWritten = 0;
                while (bytesWritten < numBytes)
                {
                    UInt64 bytesLeft = numBytes - bytesWritten;
                    byte[] writeBlock = generator.GetPadData(bytesLeft < (UInt64)writeBlockSize ? bytesLeft : (UInt64)writeBlockSize);
                    fs.Write(writeBlock, 0, writeBlock.Length);
                    bytesWritten += (UInt64)writeBlock.Length;
                }
            }
            pad = new FileInfo(pad.FullName);
        }

        public void TruncateWriteBytes(IPadDataGenerator generator, UInt64 numBytes, int writeBlockSize = DefaultWriteBlockSize)
        {
            if (writeBlockSize <= 0)
                writeBlockSize = DefaultWriteBlockSize;
            using (FileStream fs = pad.Open(FileMode.Truncate, FileAccess.Write))
            {
                index.Clear();
                UInt64 bytesWritten = 0;
                while(bytesWritten < numBytes)
                {
                    UInt64 bytesLeft = numBytes - bytesWritten;
                    byte[] writeBlock = generator.GetPadData(bytesLeft < (UInt64)writeBlockSize ? bytesLeft : (UInt64)writeBlockSize);
                    fs.Write(writeBlock, 0, writeBlock.Length);
                    bytesWritten += (UInt64)writeBlock.Length;
                }
            }
            pad = new FileInfo(pad.FullName);
        }

        public override byte[] GetPadBytes(UInt64 start, UInt64 size)
        {
            if (UInt64.MaxValue - size < start)
                throw new InvalidChunkException("Chunk end exceeds UInt64.MaxValue.");
            if(size + start > PadSize)
                throw new InvalidChunkException("Chunk end exceeds pad size.");
            using (FileStream fs = pad.Open(FileMode.Open, FileAccess.Read))
            {
                fs.Seek((long)start, SeekOrigin.Begin);
                if (size > int.MaxValue)
                {
                    byte[] finalBuffer = new byte[size];
                    byte[] tmpBuf = new byte[int.MaxValue];
                    UInt64 offset = 0;
                    int bytesRead = 0;
                    do
                    {
                        int sizeToRead = ((size - offset) < int.MaxValue) ? (int)(size - offset) : int.MaxValue;
                        bytesRead = fs.Read(tmpBuf, 0, sizeToRead);
                        if (bytesRead > 0)
                            Array.Copy(tmpBuf, 0, finalBuffer, (long)offset, bytesRead);
                        offset += (UInt64)bytesRead;
                    } while (offset < size && bytesRead > 0);
                    if(offset < size)
                    {
                        throw new PadIncompleteReadException();
                    }
                    index.Update(new PadChunk(start, offset));
                    return finalBuffer;
                }
                else
                {
                    int intSize = (int)size;
                    byte[] buffer = new byte[size];
                    int bytesRead = 0;
                    int totalBytesRead = 0;
                    do
                    {
                        bytesRead = fs.Read(buffer, totalBytesRead, (intSize) - totalBytesRead);
                        totalBytesRead += bytesRead;
                    } while (totalBytesRead < intSize && bytesRead > 0);
                    if(totalBytesRead < intSize)
                    {
                        throw new PadIncompleteReadException();
                    }
                    index.Update(new PadChunk(start, (UInt64)totalBytesRead));
                    return buffer;
                }
            }
        }

#if DEBUG
        private const string ClassName = "SimplePad";

        private static bool WriteTestResult(string testName, bool success)
        {
            return UtilityFunctions.WriteTestResult(ClassName, testName, success);
        }

        public static bool RunTest()
        {
            SimplePad pad = null;
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            try
            {
                bool testSuccess = true;
                const ulong testPadSize = 4096;
                FileInfo padFile = new FileInfo("test.pad");
                FileInfo idxFile = new FileInfo("test.idx");
                pad = SimplePad.Create(padFile, idxFile, CryptoAlgorithmCache.Instance.RNGs.First(), testPadSize);

                bool sizeAccurate = pad.PadSize == testPadSize;
                testSuccess &= WriteTestResult("Size", sizeAccurate);

                PadChunk[] chunks = pad.UnusedChunks.ToArray();
                bool chunksAccurate = chunks.Length == 1 && chunks[0].Start == 0UL && chunks[0].Size == testPadSize;
                testSuccess &= WriteTestResult("Initial Chunk", chunksAccurate);

                byte[] padBytes = pad.GetFirstUnusedPadBytes(8);
                testSuccess &= WriteTestResult("1st Bytes Size", padBytes.LongLength == 8L);

                byte[] padBytes2 = pad.GetFirstUnusedPadBytes(8);
                testSuccess &= WriteTestResult("2nd Bytes Size", padBytes2.LongLength == 8L);
                testSuccess &= WriteTestResult("Bytes Different", !UtilityFunctions.ByteArraysEqual(padBytes, padBytes2));

                chunks = pad.UnusedChunks.ToArray();
                chunksAccurate = chunks.Length == 1 && chunks[0].Start == 16UL && chunks[0].Size == testPadSize - 16UL;
                testSuccess &= WriteTestResult("Chunks Updated", chunksAccurate);

                byte[] padBytes3 = pad.GetPadBytes(32UL, 16);
                testSuccess &= WriteTestResult("3nd Bytes Size", padBytes3.LongLength == 16L);

                chunks = pad.UnusedChunks.ToArray();
                chunksAccurate = chunks.Length == 2 && chunks[0].Start == 16UL && chunks[0].Size == 16UL && chunks[1].Start == 48UL && chunks[1].Size == testPadSize - 48UL;
                testSuccess &= WriteTestResult("Noncontiguous Chunks Updated", chunksAccurate);

                padFile = pad.PadFileInfo;
                idxFile = pad.IndexFileInfo;
                pad = null;
                pad = new SimplePad(padFile, idxFile);
                byte[] padBytesRedux = pad.GetPadBytes(0, 8);
                byte[] padBytes2Redux = pad.GetPadBytes(8, 8);
                byte[] padBytes3Redux = pad.GetPadBytes(32, 16);
                chunks = pad.UnusedChunks.ToArray();
                sizeAccurate = pad.PadSize == testPadSize;
                chunksAccurate = chunks.Length == 2 && chunks[0].Start == 16UL && chunks[0].Size == 16UL && chunks[1].Start == 48UL && chunks[1].Size == testPadSize - 48UL;
                testSuccess &= WriteTestResult("Pad Loading Size", sizeAccurate);
                testSuccess &= WriteTestResult("Pad Loading Chunks", chunksAccurate);
                testSuccess &= WriteTestResult("Pad Loading Bytes Read", UtilityFunctions.ByteArraysEqual(padBytes, padBytesRedux));
                testSuccess &= WriteTestResult("Pad Loading Bytes Read 2", UtilityFunctions.ByteArraysEqual(padBytes2, padBytes2Redux));
                testSuccess &= WriteTestResult("Pad Loading Bytes Read 3", UtilityFunctions.ByteArraysEqual(padBytes3, padBytes3Redux));

                return testSuccess;
            }
            catch(Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                if(pad != null)
                {
                    try { pad.UnsafeDelete(); }
                    catch (Exception e) { UtilityFunctions.WriteTestExceptionFailure(ClassName, e); }
                }
                UtilityFunctions.WriteTestsHeaderFooter(ClassName, false);
            }
        }
#endif
    }
}
