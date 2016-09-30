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
    public interface ICryptoAlgorithm
    {
        // Return the name of the algorithm, should be unique
        string Name { get; }
        // Return a unique ID integer
        UInt32 UID { get; }
        // Return the block size of the algorithm
        int BlockSize { get; }
        // Return the key size of the algorithm for the file/buffer to encrypt
        UInt64 GetKeySize(UInt64 sizeOfFileToEncrypt);
        // Decrypt a buffer (can't be a part of a file because state won't be retained between calls)
        byte[] Decrypt(AbstractPad pad, PadChunk keyLocation, byte[] ciphertext);
        // Encrypt a buffer (can't be a part of a file because state won't be retained between calls)
        byte[] Encrypt(AbstractPad pad, PadChunk keyLocation, byte[] plaintext);
        // Decrypt a series of buffers (e.g. a file); buffers will be in a multiple of Blocksize
        IEnumerable<byte[]> Decrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> ciphertextChunks);
        // Encrypt a series of buffers (e.g. a file); buffers will be in a multiple of Blocksize
        IEnumerable<byte[]> Encrypt(AbstractPad pad, PadChunk keyLocation, IEnumerable<byte[]> plaintextChunks);
        // Return the size of the algorithm-specific header
        uint HeaderSize { get; }
        // Return the header for the algorithm as configured (new byte[0] if no header)
        byte[] Header { get; }
    }
}
