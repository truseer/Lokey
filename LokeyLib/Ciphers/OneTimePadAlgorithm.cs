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

namespace LokeyLib
{
    public class OneTimePadAlgorithm : ICryptoAlgorithm
    {
        private class OneTimePadChunkEnumerable : IEnumerable<byte[]>
        {
            private class OneTimePadChunkEnumerator : IEnumerator<byte[]>
            {
                public OneTimePadChunkEnumerator(IEnumerable<byte[]> chunkProvider,
                    AbstractPad pad, PadChunk keyChunk)
                {
                    chunkIterator = chunkProvider.GetEnumerator();
                    this.pad = pad;
                    this.keyChunk = keyChunk;
                }

                private IEnumerator<byte[]> chunkIterator;
                private AbstractPad pad;
                private PadChunk keyChunk;
                private UInt64 dataProvided = 0;
                private byte[] currentChunk = null;

                public byte[] Current { get { return currentChunk; } }

                object IEnumerator.Current { get { return currentChunk; } }

                public void Dispose() { }

                public bool MoveNext()
                {
                    bool hasNext = chunkIterator.MoveNext();
                    if (hasNext)
                    {
                        UInt64 currentStart = keyChunk.Start + dataProvided;
                        UInt64 currentSize = ((UInt64)chunkIterator.Current.LongLength <= (keyChunk.Size - dataProvided))
                            ? (UInt64)chunkIterator.Current.LongLength : (keyChunk.Size - dataProvided);
                        currentChunk = OneTimePadAlgorithm.ApplyOTP(pad.GetPadBytes(currentStart, currentSize), chunkIterator.Current);
                        dataProvided += currentSize;
                    }
                    return hasNext;
                }

                public void Reset()
                {
                    chunkIterator.Reset();
                    dataProvided = 0;
                    currentChunk = null;
                }
            }

            public OneTimePadChunkEnumerable(IEnumerable<byte[]> chunkProvider,
                AbstractPad pad, PadChunk keyChunk)
            {
                this.chunkProvider = chunkProvider;
                this.pad = pad;
                this.keyChunk = keyChunk;
            }

            private IEnumerable<byte[]> chunkProvider;
            private AbstractPad pad;
            private PadChunk keyChunk;

            private IEnumerator<byte[]> GenerateEnumerator()
            {
                return new OneTimePadChunkEnumerator(chunkProvider, pad, keyChunk);
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

        public const uint AlgorithmUID = 1;

        public const string AlgorithmName = "One-Time Pad";

        public const int AlgorithmBlockSize = 1;

        public uint UID { get { return AlgorithmUID; } }

        public string Name { get { return AlgorithmName; } }

        public int BlockSize { get { return AlgorithmBlockSize; } }

        public uint HeaderSize { get { return 0; } }

        public byte[] Header { get { return new byte[0]; } }

        private static byte[] ApplyOTPInPlace(byte[] key, byte[] text)
        {
            long length = key.LongLength < text.LongLength ? key.LongLength : text.LongLength;
            for (long i = 0; i < length; ++i)
            {
                text[i] ^= key[i];
                key[i] = 0;
            }
            return text;
        }

        private static byte[] ApplyOTP(byte[] key, byte[] text)
        {
            long length = key.LongLength < text.LongLength ? key.LongLength : text.LongLength;
            byte[] outText = new byte[text.LongLength];
            for (long i = 0; i < length; ++i)
            {
                outText[i] = (byte)(text[i] ^ key[i]);
                key[i] = 0;
            }
            return outText;
        }

        public IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks)
        {
            return new OneTimePadChunkEnumerable(ciphertextChunks, pad, keyLocation);
        }

        public byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext)
        {
            return Encrypt(pad, keyLocation, ciphertext);
        }

        public IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks)
        {
            return new OneTimePadChunkEnumerable(plaintextChunks, pad, keyLocation);
        }

        public byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext)
        {
            byte[] key = keyLocation.Size == (UInt64)plaintext.LongLength 
                ? pad.GetPadBytes(keyLocation) 
                : pad.GetPadBytes(keyLocation.Start, (UInt64)plaintext.LongLength);
            return ApplyOTP(key, plaintext);
        }

        public ulong GetKeySize(ulong sizeOfFileToEncrypt)
        {
            return sizeOfFileToEncrypt;
        }
    }
}
