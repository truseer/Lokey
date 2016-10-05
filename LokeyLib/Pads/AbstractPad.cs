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
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LokeyLib
{
    public abstract class AbstractPad : IFileComponentListable
    {
        private class AbstractPadBlockEnumerable : IEnumerable<byte[]>
        {
            private class AbstarctPadBlockEnumerator : IEnumerator<byte[]>
            {
                public AbstarctPadBlockEnumerator(AbstractPad pad, PadChunk chunkToRead, UInt64 blockSize)
                {
                    this.pad = pad;
                    this.chunk = chunkToRead;
                    this.blockSize = blockSize;
                    this.currentOffset = 0;
                    this.uninitialized = true;
                }

                private AbstractPad pad;
                private PadChunk chunk;
                private UInt64 blockSize;
                private UInt64 currentOffset;
                private bool uninitialized;

                private byte[] GetCurrent()
                {
                    return (currentOffset >= chunk.Size) 
                        ? null 
                        : pad.GetPadBytes(chunk.Start + currentOffset, 
                            (chunk.Size - currentOffset < blockSize) 
                            ? (chunk.Size - currentOffset) 
                            : blockSize); 
                }

                public byte[] Current
                {
                    get
                    {
                        return GetCurrent();
                    }
                }

                object IEnumerator.Current
                {
                    get
                    {
                        return GetCurrent();
                    }
                }

                public void Dispose() { }

                public bool MoveNext()
                {
                    if (uninitialized)
                    {
                        currentOffset = 0;
                        uninitialized = false;
                    }
                    else
                    {
                        currentOffset += blockSize;
                    }
                    return currentOffset >= chunk.Size;
                }

                public void Reset()
                {
                    uninitialized = true;
                }
            }

            public AbstractPadBlockEnumerable(AbstractPad pad, PadChunk freeChunk, UInt64 totalBytesToRead, UInt64 blockSize)
            {
                this.pad = pad;
                this.chunk = (totalBytesToRead >= freeChunk.Size) 
                    ? freeChunk 
                    : new PadChunk(freeChunk.Start, totalBytesToRead);
                this.blockSize = blockSize;
            }

            private AbstractPad pad;
            private PadChunk chunk;
            private UInt64 blockSize;

            private IEnumerator<byte[]> GenerateEnumerator()
            {
                return new AbstarctPadBlockEnumerator(pad, chunk, blockSize);
            }

            public IEnumerator<byte[]> GetEnumerator()
            {
                return GenerateEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GenerateEnumerator();
            }
        }

        public abstract string Identifier { get; }

        public abstract bool IsValid { get; }

        public abstract UInt64 PadSize { get; }

        public abstract void UnsafeDelete();

        // These should mark the chunk grabbed as used
        public abstract byte[] GetPadBytes(UInt64 start, UInt64 size);

        public byte[] GetPadBytes(PadChunk chunk) { return GetPadBytes(chunk.Start, chunk.Size); }

        public abstract IEnumerable<PadChunk> UnusedChunks { get; }

        public abstract IEnumerable<FileInfo> ComponentFiles { get; }

        public PadChunk GetFirstUnusedChunk()
        {
            return UnusedChunks.First();
        }

        public PadChunk GetFirstUnusedChunk(UInt64 ofSize)
        {
            return UnusedChunks.First(chunk => chunk.Size >= ofSize);
        }

        public byte[] GetFirstUnusedPadBytes(UInt64 ofSize)
        {
            return GetPadBytes(GetFirstUnusedChunk(ofSize).Start, ofSize);
        }

        public IEnumerable<byte[]> GetFirstUnusedPadBytesByBlock(UInt64 ofSize, UInt64 blockSize)
        {
            return new AbstractPadBlockEnumerable(this, GetFirstUnusedChunk(ofSize), ofSize, blockSize);
        }
    }
}
