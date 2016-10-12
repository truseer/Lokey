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
using System.Collections.Generic;

namespace LokeyLib
{
    public class CounterMode : IStreamCipher, ICryptoAlgorithm
    {
        private IBlockCipher blockCipher;

        public CounterMode(IBlockCipher blockCipher)
        {
            this.blockCipher = blockCipher;
        }

        public int BlockSize { get { return 1; } }

        public byte[] Header { get { return new byte[0]; } }

        public uint HeaderSize { get { return 0; } }

        public int IvLength { get { return blockCipher.BlockLength; } }

        public int KeyLength { get { return blockCipher.KeyLength; } }

        public string Name { get { return blockCipher.Name + "-Counter_Mode"; } }

        public uint UID { get { return blockCipher.UID; } }

        public void Decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] plaintext, ulong startingOffset = 0)
        {
            if (ciphertext.LongLength != plaintext.LongLength)
                throw new InvalidOperationException("Plaintext and ciphertext buffer lengths must match");
            if (iv.Length != IvLength)
                throw new InvalidOperationException("Invalid IV length");
            if (key.Length != KeyLength)
                throw new InvalidOperationException("Invalid key length");
            byte[] ctrBlock = new byte[blockCipher.BlockLength];
            byte[] keyStreamBlock = new byte[blockCipher.BlockLength];
            ulong startingBlock = startingOffset / (ulong)blockCipher.BlockLength;
            CounterNonce ctr = new CounterNonce(iv, startingBlock);
            uint blockByte = (uint)(startingOffset % (ulong)blockCipher.BlockLength);
            long bytesProcessed = 0L;
            while(bytesProcessed < ciphertext.LongLength)
            {
                ctr.GetCountedNonce(ctrBlock);
                ctr.Increment();
                blockCipher.EncryptBlock(key, ctrBlock, keyStreamBlock);
                while (bytesProcessed < ciphertext.LongLength && blockByte < keyStreamBlock.Length)
                {
                    plaintext[bytesProcessed] = (byte)(ciphertext[bytesProcessed] ^ keyStreamBlock[blockByte]);
                    ++bytesProcessed;
                    ++blockByte;
                }
                blockByte = 0U;
            }
        }

        public void Encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] ciphertext, ulong startingOffset = 0)
        {
            // Encryption and decryption are the same operation in counter mode
            Decrypt(key, iv, plaintext, ciphertext, startingOffset);
        }

        public IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks)
        {
            KeyIVPair ki = GetKeyIvPairFromPad(pad, keyLocation);
            return this.Encrypt(ki, plaintextChunks);
        }

        public byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext)
        {
            KeyIVPair ki = GetKeyIvPairFromPad(pad, keyLocation);
            byte[] ciphertext = new byte[plaintext.LongLength];
            Encrypt(ki.Key, ki.IV, plaintext, ciphertext);
            return ciphertext;
        }

        public IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks)
        {
            KeyIVPair ki = GetKeyIvPairFromPad(pad, keyLocation);
            return this.Decrypt(ki, ciphertextChunks);
        }

        public byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext)
        {
            // Encryption and decryption are the same operation in counter mode
            return Encrypt(pad, keyLocation, ciphertext);
        }

        public ulong GetKeySize(ulong sizeOfFileToEncrypt)
        {
            return (ulong)(KeyLength + IvLength);
        }

        private KeyIVPair GetKeyIvPairFromPad(AbstractPad pad, PadChunk keyLocation)
        {
            if (keyLocation.Size < (ulong)(KeyLength + IvLength))
                throw new InvalidChunkException("The specified key chunk is too small");
            byte[] padBytes = pad.GetPadBytes(keyLocation);
            byte[] key = new byte[KeyLength];
            byte[] iv = new byte[IvLength];
            Array.Copy(padBytes, key, key.LongLength);
            Array.Copy(padBytes, key.LongLength, iv, 0L, iv.LongLength);
            return new KeyIVPair(key, iv);
        }

        public void Dispose()
        {
        }
    }
}
