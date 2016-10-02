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
using System.Security.Cryptography;

namespace LokeyLib
{
    public abstract class AbstractAesAlgorithm : ICryptoAlgorithm
    {
        protected class KeyIVPair
        {
            public KeyIVPair(byte[] key, byte[] iv)
            {
                Key = key;
                IV = iv;
            }

            public byte[] Key { get; }
            public byte[] IV { get; }
        }

        protected class AesChunkEnumerable : IEnumerable<byte[]>
        {
            protected class AesChunkEnumerator : IEnumerator<byte[]>
            {
                private ICryptoTransform xform;
                private IEnumerator<byte[]> iterator;
                private byte[] currentChunk;
                private byte[] nextChunk;
                protected AesManaged aes;
                protected KeyIVPair keyivPair;
                protected bool encrypt;

                public AesChunkEnumerator(AesManaged aes, KeyIVPair keyivPair,
                    IEnumerable<byte[]> iterable, bool encrypt)
                {
                    currentChunk = null;
                    this.aes = aes;
                    this.keyivPair = keyivPair;
                    this.encrypt = encrypt;
                    xform = encrypt ? aes.CreateEncryptor(keyivPair.Key, keyivPair.IV)
                        : aes.CreateDecryptor(keyivPair.Key, keyivPair.IV);
                    iterator = iterable.GetEnumerator();
                    if (iterator.MoveNext())
                        nextChunk = iterator.Current;
                }

                public byte[] Current { get { return currentChunk; } }

                object IEnumerator.Current { get { return currentChunk; } }

                public void Dispose()
                {
                    xform.Dispose();
                }

                public bool MoveNext()
                {
                    if (nextChunk != null)
                    {
                        byte[] inputBlocks = nextChunk;
                        nextChunk = iterator.MoveNext() ? iterator.Current : null;
                        int numFullBlocks = inputBlocks.Length / xform.InputBlockSize;
                        int numPartialBlocks = inputBlocks.Length % xform.InputBlockSize != 0 ? 1 : 0;
                        byte[] outputBlocks = new byte[(numFullBlocks + numPartialBlocks) * xform.OutputBlockSize];
                        bool containsFinalBlock = nextChunk == null;
                        int blocksToProcessNormally = (containsFinalBlock && numPartialBlocks == 0) ? numFullBlocks - 1 : numFullBlocks;
                        int outputOffset, blockNum;
                        for (blockNum = 0, outputOffset = 0; blockNum < blocksToProcessNormally && outputOffset < outputBlocks.Length; ++blockNum)
                        {
                            outputOffset += xform.TransformBlock(inputBlocks,
                                blockNum * xform.InputBlockSize, xform.InputBlockSize,
                                outputBlocks, outputOffset);
                        }
                        if (containsFinalBlock)
                        {
                            int inputOffset = blockNum * xform.InputBlockSize;
                            byte[] finalBlock = xform.TransformFinalBlock(inputBlocks, inputOffset, inputBlocks.Length - inputOffset);
                            Array.Resize(ref outputBlocks, outputOffset + finalBlock.Length);
                            Array.Copy(finalBlock, 0, outputBlocks, outputOffset, finalBlock.Length);
                        }
                        else
                        {
                            Array.Resize(ref outputBlocks, outputOffset);
                        }
                        currentChunk = outputBlocks;
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }

                public void Reset()
                {
                    currentChunk = null;
                    xform = encrypt ? aes.CreateEncryptor(keyivPair.Key, keyivPair.IV)
                        : aes.CreateDecryptor(keyivPair.Key, keyivPair.IV);
                    iterator.Reset();
                    nextChunk = iterator.MoveNext() ? iterator.Current : null;
                }
            }

            public AesChunkEnumerable(AesManaged aes, KeyIVPair keyivPair, 
                IEnumerable<byte[]> chunkProvider, bool encrypt)
            {
                this.aes = aes;
                this.chunkProvider = chunkProvider;
                this.encrypt = encrypt;
                this.keyivPair = keyivPair;
            }

            protected AesManaged aes;
            protected IEnumerable<byte[]> chunkProvider;
            protected KeyIVPair keyivPair;
            protected bool encrypt;

            protected IEnumerator<byte[]> GenerateEnumerator()
            {
                return new AesChunkEnumerator(aes, keyivPair, chunkProvider, encrypt);
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

        protected AbstractAesAlgorithm(int keySize, CipherMode mode,
            PaddingMode padding = PaddingMode.PKCS7)
        {
            algorithm.BlockSize = 128;
            algorithm.KeySize = keySize;
            algorithm.Mode = mode;
            algorithm.Padding = padding;
        }

        ~AbstractAesAlgorithm()
        {
            algorithm.Dispose();
        }

        protected AesManaged algorithm = new AesManaged();

        public byte[] Header { get { return new byte[0]; } }

        public uint HeaderSize { get { return 0; } }

        public string Name
        {
            get
            {
                return "AES" + algorithm.KeySize.ToString() + algorithm.Mode.ToString() 
                    + "-Padding:" + algorithm.Padding.ToString();
            }
        }

        public int BlockSize { get { return algorithm.BlockSize / 8; } }

        public abstract uint UID { get; }

        protected abstract KeyIVPair GetKeyIVPair(AbstractPad pad, PadChunk keyLocation);

        public abstract ulong GetKeySize(ulong sizeOfFileToEncrypt);

        public IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks)
        {
            return new AesChunkEnumerable(algorithm, GetKeyIVPair(pad, keyLocation), ciphertextChunks, false);
        }

        public IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks)
        {
            return new AesChunkEnumerable(algorithm, GetKeyIVPair(pad, keyLocation), plaintextChunks, true);
        }

        private static byte[] TransformBlocks(KeyIVPair keyiv, ICryptoTransform xform, byte[] inputBlocks)
        {
            int numBlocks = inputBlocks.Length / xform.InputBlockSize;
            if (inputBlocks.Length % xform.InputBlockSize != 0) ++numBlocks;
            byte[] outputBlocks = new byte[numBlocks * xform.OutputBlockSize];
            int inBlock = 0;
            int outBlockOffset = 0;
            for (; inBlock < numBlocks - 1; ++inBlock)
            {
                outBlockOffset += xform.TransformBlock(inputBlocks,
                    inBlock * xform.InputBlockSize,
                    xform.InputBlockSize,
                    outputBlocks,
                    outBlockOffset);
            }
            byte[] finalXform = xform.TransformFinalBlock(inputBlocks, inBlock * xform.InputBlockSize, inputBlocks.Length - (inBlock * xform.InputBlockSize));
            int totalLength = outBlockOffset + finalXform.Length;
            Array.Resize(ref outputBlocks, totalLength);
            Array.Copy(finalXform, 0, outputBlocks, outBlockOffset, finalXform.Length);
            return outputBlocks;
        }

        public byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext)
        {
            KeyIVPair keyiv = GetKeyIVPair(pad, keyLocation);
            using (ICryptoTransform xform = algorithm.CreateDecryptor(keyiv.Key, keyiv.IV))
            {
                return TransformBlocks(keyiv, xform, ciphertext);
            }
        }

        public byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext)
        {
            KeyIVPair keyiv = GetKeyIVPair(pad, keyLocation);
            using (ICryptoTransform xform = algorithm.CreateEncryptor(keyiv.Key, keyiv.IV))
            {
                return TransformBlocks(keyiv, xform, plaintext);
            }
        }
    }
}
