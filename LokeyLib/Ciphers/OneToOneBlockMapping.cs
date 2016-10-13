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
using System.Numerics;

namespace LokeyLib
{
    public class OneToOneBlockMapping : IBlockCipher
    {
        private BigInteger maxKey;

        private byte[] encryptionLookupTable;

        private byte[] decryptionLookupTable;

        private byte[] key = null;

        private BigInteger Factorial()
        {
            long maxValPlusOne = NumberOfBlockValues;
            BigInteger accumulator = new BigInteger(maxValPlusOne);
            while (--maxValPlusOne > 1L)
                accumulator = BigInteger.Multiply(accumulator, new BigInteger(maxValPlusOne));
            return accumulator;
        }

        // anything bigger than 3 is gonna crash unless you've got some special sauce, and 3 is pretty big
        public OneToOneBlockMapping(int blockSize)
        {
            if (blockSize < 1 || blockSize >= sizeof(ulong))
                throw new InvalidOperationException("OneToOneBlockMapping only valid for block sizes >= 1 and < 8");
            BlockLength = blockSize;
            switch(blockSize)
            {
                case 1:
                    {
                        byte[] maxKeyBytes = OneToOneBlockMappingMaxKeyArrays.MaxBytePlusOneFactorial;
                        KeyLength = maxKeyBytes.Length;
                        maxKey = new BigInteger(maxKeyBytes);
                    }
                    break;
                case 2:
                    {
                        byte[] maxKeyBytes = OneToOneBlockMappingMaxKeyArrays.MaxUshortPlusOneFactorial;
                        KeyLength = maxKeyBytes.Length;
                        maxKey = new BigInteger(maxKeyBytes);
                    }
                    break;
                default:
                    {
                        maxKey = Factorial();
                        byte[] maxKeyBytes = maxKey.ToByteArray();
                        KeyLength = maxKeyBytes.Length;
                    }
                    break;
            }
            encryptionLookupTable = new byte[NumberOfBlockValues * BlockLength];
            decryptionLookupTable = new byte[NumberOfBlockValues * BlockLength];
        }

        private void BuildLookupTables()
        {
            InitializeEncryptionArray();
            // Should do some validation to ensure an even distribution
            BigInteger keyVal = new BigInteger(key);
            for(long element = NumberOfBlockValues - 1L; element > 0; --element)
            {
                BigInteger swapIdx;
                keyVal = BigInteger.DivRem(keyVal, new BigInteger(element), out swapIdx);
                Swap(encryptionLookupTable, (long)swapIdx, element);
                long elementValue = GetElementValue(encryptionLookupTable, element);
                SetElementValue(decryptionLookupTable, elementValue, element);
            }
        }

        private void Swap(byte[] array, long elementA, long elementB)
        {
            if (elementA != elementB)
            {
                long idxA = elementA * BlockLength;
                long idxB = elementB * BlockLength;
                byte[] tmp = new byte[BlockLength];
                Array.Copy(array, idxA, tmp, 0L, BlockLength);
                Array.Copy(array, idxB, array, idxA, BlockLength);
                Array.Copy(tmp, 0L, array, idxB, BlockLength);
            }
        }

        private void SetElementValue(byte[] array, long element, long value)
        {
            for (int byteNum = 0; byteNum < BlockLength; ++byteNum)
            {
                array[(element * BlockLength) + byteNum] = (byte)((value >> (byteNum * 8)) & byte.MaxValue);
            }
        }

        private long GetElementValue(byte[] array, long element)
        {
            long retval = 0L;
            for (int byteNum = 0; byteNum < BlockLength; ++byteNum)
            {
                retval |= ((long)array[(element * BlockLength) + byteNum]) << (byteNum * 8);
            }
            return retval;
        }

        private void InitializeEncryptionArray()
        {
            for(long i = 0L; i < NumberOfBlockValues; ++i)
            {
                SetElementValue(encryptionLookupTable, i, i);
            }
        }

        private long NumberOfBlockValues { get { return 1L << (BlockLength * 8); } }

        public int BlockLength { get; }

        public int KeyLength { get; }

        public string Name { get { return BlockLength.ToString() + "-Byte-Block-OneToOneMapping"; } }

        public uint UID { get { return 70U + (uint)BlockLength; } }

        public void DecryptBlock(byte[] key, byte[] ciphertext, byte[] plaintext)
        {
            if (this.key == null || (this.key != key && !UtilityFunctions.ByteArraysEqual(this.key, key)))
            {
                this.key = key;
                BuildLookupTables();
            }
            long ctBlockVal = GetElementValue(ciphertext, 0L);
            long ptBlockVal = GetElementValue(decryptionLookupTable, ctBlockVal);
            SetElementValue(plaintext, 0L, ptBlockVal);
        }

        public void Dispose()
        {
            maxKey = new BigInteger();
            key = null;
            encryptionLookupTable = null;
            decryptionLookupTable = null;
        }

        public void EncryptBlock(byte[] key, byte[] plaintext, byte[] ciphertext)
        {
            if (this.key == null || (this.key != key && !UtilityFunctions.ByteArraysEqual(this.key, key)))
            {
                this.key = key;
                BuildLookupTables();
            }
            long ptBlockVal = GetElementValue(plaintext, 0L);
            long ctBlockVal = GetElementValue(encryptionLookupTable, ptBlockVal);
            SetElementValue(ciphertext, 0L, ctBlockVal);
        }
    }
}
