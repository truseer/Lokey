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
using System.Linq;

namespace LokeyLib
{
    public class AesCtrNonce : IEnumerable<byte[]>
    {
        public AesCtrNonce(byte[] nonce)
        {
            EnumeratorBlockSizeBytes = BlockSizeBytes;
            Nonce = new byte[BlockSizeBytes];
            Array.Copy(nonce, Nonce, nonce.Length < BlockSizeBytes ? nonce.Length : BlockSizeBytes);
        }

        public const int BlockSize = 128;

        public const int BlockSizeBytes = BlockSize / 8;

        public long EnumeratorBlockSizeBytes { get; set; }

        public byte[] CountedNonce
        {
            get { return Nonce.Zip<byte, byte, byte>(CounterBytes, (a, b) => (byte)(a ^ b)).ToArray(); }
        }

        public byte[] Nonce { get; }

        public byte[] CounterBytes
        {
            get
            {
                byte[] ctrBytes = new byte[BlockSizeBytes];
                Array.Copy(BitConverter.GetBytes(lowCount), ctrBytes, sizeof(ulong));
                Array.Copy(BitConverter.GetBytes(highCount), 0, ctrBytes, sizeof(ulong), sizeof(ulong));
                return ctrBytes;
            }
        }

        private ulong lowCount = 0UL;

        private ulong highCount = 0UL;

        public void Increment()
        {
            if(lowCount == ulong.MaxValue)
            {
                lowCount = ulong.MinValue;
                ++highCount;
            }
            else
            {
                ++lowCount;
            }
        }

        public void Reset()
        {
            lowCount = 0UL;
            highCount = 0UL;
        }

        public byte[] GetBytes(long numBytes)
        {
            long modBytes = numBytes % BlockSizeBytes;
            if (modBytes != 0L)
                numBytes += BlockSizeBytes - modBytes;
            byte[] buffer = new byte[numBytes];
            for(long offset = 0L; offset < numBytes; offset += BlockSizeBytes)
            {
                Array.Copy(CountedNonce, 0L, buffer, offset, BlockSizeBytes);
                Increment();
            }
            return buffer;
        }

        private IEnumerator<byte[]> GenerateEnumerator()
        {
            return new AesCtrNonceEnumerator(this, EnumeratorBlockSizeBytes);
        }

        public IEnumerator<byte[]> GetEnumerator()
        {
            return GenerateEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GenerateEnumerator();
        }

        private class AesCtrNonceEnumerator : IEnumerator<byte[]>
        {
            private AesCtrNonce Nonce { get; }
            private long EnumeratorsBlockSizeBytes { get; }
            private byte[] currentChunk = null;
            private byte[] spareBytes = null;
            private long bytesOffset = 0L;

            public AesCtrNonceEnumerator(AesCtrNonce aesCtrNonce, long enumeratorBlockSizeBytes)
            {
                Nonce = aesCtrNonce;
                EnumeratorsBlockSizeBytes = enumeratorBlockSizeBytes;
            }

            public byte[] Current { get { return currentChunk; } }

            object IEnumerator.Current { get { return currentChunk; } }

            public void Dispose() { }

            public bool MoveNext()
            {
                currentChunk = new byte[EnumeratorsBlockSizeBytes];
                long bytesCopied = 0;
                while (bytesCopied < currentChunk.LongLength)
                {
                    if (spareBytes == null || bytesOffset >= spareBytes.LongLength)
                    {
                        spareBytes = Nonce.GetBytes(EnumeratorsBlockSizeBytes);
                        bytesOffset = 0L;
                    }
                    long availableSpareBytes = spareBytes.LongLength - bytesOffset;
                    long currentChunkBytesNeeded = EnumeratorsBlockSizeBytes - bytesCopied;
                    long bytesToCopy = availableSpareBytes < currentChunkBytesNeeded ? availableSpareBytes : currentChunkBytesNeeded;
                    Array.Copy(spareBytes, bytesOffset, currentChunk, bytesCopied, bytesToCopy);
                    bytesCopied += bytesToCopy;
                    bytesOffset += bytesToCopy;
                }
                return true;
            }

            public void Reset()
            {
                currentChunk = null;
                spareBytes = null;
                bytesOffset = 0L;
                Nonce.Reset();
            }
        }
    }
}
