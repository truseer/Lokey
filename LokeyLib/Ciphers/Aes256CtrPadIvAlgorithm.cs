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


﻿using System.Collections.Generic;
using System.Linq;

namespace LokeyLib
{
    public class Aes256CtrPadIvAlgorithm : ICryptoAlgorithm
    {
        private Aes256EcbPadIvAlgorithm ecb = new Aes256EcbPadIvAlgorithm();

        public int BlockSize { get { return ecb.BlockSize; } }

        public byte[] Header { get { return ecb.Header; } }

        public uint HeaderSize { get { return ecb.HeaderSize; } }

        public string Name { get { return ecb.Name.ToUpperInvariant().Replace("ECB", "CTR"); } }

        public uint UID { get { return 4; } }

        public IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks)
        {
            return Encrypt(pad, keyLocation, ciphertextChunks);
        }

        public byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext)
        {
            return Encrypt(pad, keyLocation, ciphertext);
        }

        public IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks)
        {
            AesCtrNonce nonce = new AesCtrNonce(pad.GetPadBytes(new PadChunk(keyLocation.Start, (ulong)BlockSize)));
            PadChunk ecbKey = new PadChunk(keyLocation.Start + (ulong)BlockSize, ecb.GetKeySize(ulong.MaxValue));
            long chunkSize = plaintextChunks.First().LongLength;
            nonce.EnumeratorBlockSizeBytes = chunkSize;
            return ecb.Encrypt(pad, ecbKey, nonce).Zip(plaintextChunks, (ctrPad, chunk) => ctrPad.Zip(chunk, (a, b) => (byte)(a ^ b)).ToArray());
        }

        public byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext)
        {
            AesCtrNonce nonce = new AesCtrNonce(pad.GetPadBytes(new PadChunk(keyLocation.Start, (ulong)BlockSize)));
            PadChunk ecbKey = new PadChunk(keyLocation.Start + (ulong)BlockSize, ecb.GetKeySize((ulong)plaintext.LongLength));
            byte[] ctrPad = nonce.GetBytes(plaintext.LongLength);
            ctrPad = ecb.Encrypt(pad, ecbKey, ctrPad);
            byte[] ciphertext = new byte[plaintext.LongLength];
            for(long offset = 0L; offset < ciphertext.LongLength; ++offset)
            {
                ciphertext[offset] = (byte)(ctrPad[offset] ^ plaintext[offset]);
                ctrPad[offset] = 0;
            }
            return ciphertext;
        }

        public ulong GetKeySize(ulong sizeOfFileToEncrypt)
        {
            return ecb.GetKeySize(sizeOfFileToEncrypt) + (ulong)BlockSize;
        }
    }
}
