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

using System.Collections;
using System.Collections.Generic;

namespace LokeyLib
{
    public static class StreamCipher
    {
        public static byte[] Encrypt(this IStreamCipher cipher, byte[] key, byte[] iv, byte[] plaintext, ulong startingOffset = 0)
        {
            byte[] ciphertext = new byte[plaintext.LongLength];
            cipher.Encrypt(key, iv, plaintext, ciphertext, startingOffset);
            return ciphertext;
        }

        public static void EncryptInPlace(this IStreamCipher cipher, byte[] key, byte[] iv, byte[] buffer, ulong startingOffset = 0)
        {
            cipher.Encrypt(key, iv, buffer, buffer, startingOffset);
        }

        public static byte[] Decrypt(this IStreamCipher cipher, byte[] key, byte[] iv, byte[] ciphertext, ulong startingOffset = 0)
        {
            byte[] plaintext = new byte[ciphertext.LongLength];
            cipher.Decrypt(key, iv, ciphertext, plaintext, startingOffset);
            return plaintext;
        }

        public static void DecryptInPlace(this IStreamCipher cipher, byte[] key, byte[] iv, byte[] buffer, ulong startingOffset = 0)
        {
            cipher.Decrypt(key, iv, buffer, buffer, startingOffset);
        }

        public static IEnumerable<byte[]> Encrypt(this IStreamCipher cipher, KeyIVPair keyIvPair, IEnumerable<byte[]> plaintextChunks)
        {
            return new StreamCipherEnumerable(cipher, keyIvPair, plaintextChunks, true);
        }

        public static IEnumerable<byte[]> Encrypt(this IStreamCipher cipher, byte[] key, byte[] iv, IEnumerable<byte[]> plaintextChunks)
        {
            return cipher.Encrypt(new KeyIVPair(key, iv), plaintextChunks);
        }

        public static IEnumerable<byte[]> Decrypt(this IStreamCipher cipher, KeyIVPair keyIvPair, IEnumerable<byte[]> ciphertextChunks)
        {
            return new StreamCipherEnumerable(cipher, keyIvPair, ciphertextChunks, false);
        }

        public static IEnumerable<byte[]> Decrypt(this IStreamCipher cipher, byte[] key, byte[] iv, IEnumerable<byte[]> ciphertextChunks)
        {
            return cipher.Decrypt(new KeyIVPair(key, iv), ciphertextChunks);
        }

        private class StreamCipherEnumerable : IEnumerable<byte[]>
        {
            private IStreamCipher streamCipher;
            private KeyIVPair ki;
            private IEnumerable<byte[]> chunkEnumerable;
            private bool encrypt;

            public StreamCipherEnumerable(IStreamCipher cipher, KeyIVPair keyIvPair, IEnumerable<byte[]> chunks, bool encrypt)
            {
                ki = keyIvPair;
                streamCipher = cipher;
                chunkEnumerable = chunks;
                this.encrypt = encrypt;
            }

            public IEnumerator<byte[]> GetEnumerator()
            {
                return new StreamCipherEnumerator(streamCipher, ki, chunkEnumerable, encrypt);
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return new StreamCipherEnumerator(streamCipher, ki, chunkEnumerable, encrypt);
            }

            private class StreamCipherEnumerator : IEnumerator<byte[]>
            {
                private IStreamCipher streamCipher;
                private KeyIVPair ki;
                private ulong offset;
                private byte[] currentChunk;
                private IEnumerator<byte[]> chunkEnumerator;
                private bool encrypt;

                public StreamCipherEnumerator(IStreamCipher cipher, KeyIVPair keyIvPair, IEnumerable<byte[]> chunkEnumerable, bool encrypt)
                {
                    ki = keyIvPair;
                    streamCipher = cipher;
                    offset = 0UL;
                    currentChunk = null;
                    chunkEnumerator = chunkEnumerable.GetEnumerator();
                    this.encrypt = encrypt;
                }

                public byte[] Current { get { return currentChunk; } }

                object IEnumerator.Current { get { return currentChunk; } }

                public void Dispose() { currentChunk = null; }

                public bool MoveNext()
                {
                    if (chunkEnumerator.MoveNext())
                    {
                        currentChunk = encrypt 
                            ? streamCipher.Encrypt(ki.Key, ki.IV, chunkEnumerator.Current, offset)
                            : streamCipher.Decrypt(ki.Key, ki.IV, chunkEnumerator.Current, offset);
                        offset += (ulong)currentChunk.LongLength;
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }

                public void Reset()
                {
                    offset = 0UL;
                    currentChunk = null;
                    chunkEnumerator.Reset();
                }
            }
        }
    }
}
