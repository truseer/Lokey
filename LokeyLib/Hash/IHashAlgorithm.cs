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

using System.IO;

namespace LokeyLib
{
    public interface IHashAlgorithm
    {
        // Process the given buffer; use ComputeHash() to generate the hash after any number of calls to Process Buffer
        void ProcessBuffer(byte[] buffer);
        // Compute the hash after calls to ProcessBuffer
        byte[] ComputeHash();
        // Compute the hash for the entire stream; use this or calls to ProcessBuffer followed by the other overload of ComputeHash
        byte[] ComputeHash(Stream stream);
        // Size of the output hash in bytes
        int HashSize { get; }
        // Unique ID for the hash algorithm
        uint UID { get; }
        // Unique name for the hash algorithm
        string Name { get; }
    }
}
