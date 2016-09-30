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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    public class NoEncryptionAlgorithm : ICryptoAlgorithm
    {
        public const string AlgorithmName = "No Encyption";

        public const uint AlgorithmUID = 0;

        public const int AlgorithmBlockSize = 1;

        public string Name { get { return AlgorithmName; } }

        public uint UID { get { return AlgorithmUID; } }

        public int BlockSize {  get { return AlgorithmBlockSize; } }

        public byte[] Header { get { return new byte[0]; } }

        public uint HeaderSize { get { return 0; } }

        public IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks)
        {
            return ciphertextChunks;
        }

        public byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext)
        {
            return ciphertext;
        }

        public IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks)
        {
            return plaintextChunks;
        }

        public byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext)
        {
            return plaintext;
        }

        public ulong GetKeySize(ulong sizeOfFileToEncrypt)
        {
            return 0;
        }
    }
}
