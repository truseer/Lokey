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
using System.Security.Cryptography;

namespace LokeyLib
{
    public class AesBlockCipher : IBlockCipher
    {
        public enum AesKeyLength
        {
            _128Bits,
            _192Bits,
            _256Bits
        }

        private static int ToKeyLength(AesKeyLength keySize)
        {
            switch(keySize)
            {
                case AesKeyLength._128Bits:
                    return 128;
                case AesKeyLength._192Bits:
                    return 192;
                case AesKeyLength._256Bits:
                    return 256;
                default:
                    throw new InvalidOperationException("The given enumeration value is invalid.");
            }
        }

        private AesManaged aes;
        private byte[] key = null;
        private ICryptoTransform decryptor = null;
        private ICryptoTransform encryptor = null;

        public AesBlockCipher(AesKeyLength keySize)
        {
            aes = new AesManaged()
            {
                Mode = CipherMode.ECB,
                KeySize = ToKeyLength(keySize),
                Padding = PaddingMode.None,
            };
        }

        public int BlockLength { get { return aes.BlockSize / 8; } }

        public int KeyLength { get { return aes.KeySize / 8; } }

        public string Name { get { return "AES-" + aes.KeySize.ToString(); } }

        public uint UID
        {
            get
            {
                switch (aes.KeySize)
                {
                    case 128:
                        return 11;
                    case 192:
                        return 12;
                    case 256:
                        return 13;
                    default:
                        throw new InvalidOperationException("The given enumeration value is invalid.");
                }
            }
        }

        public void DecryptBlock(byte[] key, byte[] ciphertext, byte[] plaintext)
        {
            if (this.key != key)
            {
                this.key = key;
                if (decryptor != null)
                    decryptor.Dispose();
                decryptor = aes.CreateDecryptor(key, aes.IV);
                if (encryptor != null)
                {
                    encryptor.Dispose();
                    encryptor = null;
                }
            }
            else if(decryptor == null)
            {
                decryptor = aes.CreateDecryptor(key, aes.IV);
            }
            if(decryptor.TransformBlock(ciphertext, 0, ciphertext.Length, plaintext, 0) != plaintext.Length)
            {
                throw new TransformException("The transform failed to produce the expected block.");
            }
        }

        public void EncryptBlock(byte[] key, byte[] plaintext, byte[] ciphertext)
        {
            if (this.key != key)
            {
                this.key = key;
                if (encryptor != null)
                    encryptor.Dispose();
                encryptor = aes.CreateEncryptor(key, aes.IV);
                if(decryptor != null)
                {
                    decryptor.Dispose();
                    decryptor = null;
                }
            }
            else if (encryptor == null)
            {
                encryptor = aes.CreateEncryptor(key, aes.IV);
            }
            if(encryptor.TransformBlock(plaintext, 0, plaintext.Length, ciphertext, 0) != ciphertext.Length)
            {
                throw new TransformException("The transform failed to produce the expected block.");
            }
        }

        public void Dispose()
        {
            key = null;
            if (aes != null)
            {
                aes.Dispose();
            }
            if(encryptor != null)
            {
                encryptor.Dispose();
                encryptor = null;
            }
            if(decryptor != null)
            {
                decryptor.Dispose();
                decryptor = null;
            }
        }
    }
}
