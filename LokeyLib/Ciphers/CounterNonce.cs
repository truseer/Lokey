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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    public class CounterNonce
    {
        private byte[] nonce;
        private ulong counter;

        public CounterNonce(byte[] nonce, ulong counterStart = 0UL)
        {
            this.nonce = nonce;
            counter = counterStart;
        }

        public void Increment() { ++counter; }

        public byte[] GetCountedNonce()
        {
            byte[] countedNonce = new byte[nonce.Length];
            GetCountedNonceToBuffer(countedNonce);
            return countedNonce;
        }

        public void GetCountedNonce(byte[] countedNonce)
        {
            if (countedNonce.Length != nonce.Length)
                throw new InvalidOperationException("Output nonce array is not the same size as the nonce.");
            GetCountedNonceToBuffer(countedNonce);
        }

        private void GetCountedNonceToBuffer(byte[] countedNonce)
        {
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);
            int i;
            for (i = 0; i < counterBytes.Length && i < nonce.Length; ++i)
                countedNonce[i] = (byte)(nonce[i] ^ counterBytes[i]);
            if (i < nonce.Length)
                Array.Copy(nonce, i, countedNonce, i, nonce.Length - i);
        }
    }
}
