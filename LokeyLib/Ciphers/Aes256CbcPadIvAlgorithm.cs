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
using System.Security.Cryptography;

namespace LokeyLib
{
    public class Aes256CbcPadIvAlgorithm : AbstractAesAlgorithm
    {
        public const int KeySize = 256;

        public Aes256CbcPadIvAlgorithm() : base(KeySize, CipherMode.CBC) { }

        public override uint UID { get { return 2; } }

        public override ulong GetKeySize(ulong sizeOfFileToEncrypt)
        {
            return (ulong)((KeySize / 8) + BlockSize);
        }

        protected override KeyIVPair GetKeyIVPair(AbstractPad pad, PadChunk keyLocation)
        {
            byte[] padBytes = pad.GetPadBytes(keyLocation);
            byte[] key = new byte[KeySize / 8];
            byte[] iv = new byte[BlockSize];
            Array.Copy(padBytes, key, key.Length);
            Array.Copy(padBytes, key.Length, iv, 0, iv.Length);
            return new KeyIVPair(key, iv);
        }
    }
}
