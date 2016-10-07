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

namespace LokeyLib
{
    public class PadChunk : IEquatable<PadChunk>
    {
        public PadChunk(UInt64 start, UInt64 size)
        {
            Start = start;
            Size = size;
        }

        public UInt64 Start { get; }
        public UInt64 Size { get; }
        public UInt64 End { get { return Start + Size; } }

        public bool Overlap(PadChunk other)
        {
            return (other.Start >= Start && other.Start < End) || (Start >= other.Start && Start < other.End);
        }

        public byte[] ToBytes()
        {
            byte[] startBytes = BitConverter.GetBytes(Start);
            UtilityFunctions.EndianSwap(startBytes);
            byte[] sizeBytes = BitConverter.GetBytes(Size);
            UtilityFunctions.EndianSwap(sizeBytes);
            byte[] chunkBytes = new byte[startBytes.Length + sizeBytes.Length];
            Array.Copy(startBytes, chunkBytes, startBytes.Length);
            Array.Copy(sizeBytes, 0, chunkBytes, startBytes.Length, sizeBytes.Length);
            return chunkBytes;
        }

        public static PadChunk FromBytes(byte[] bytes, int offset = 0)
        {
            UtilityFunctions.EndianSwapRange(bytes, offset, sizeof(ulong));
            UInt64 start = BitConverter.ToUInt64(bytes, offset);
            UtilityFunctions.EndianSwapRange(bytes, sizeof(UInt64) + offset, sizeof(ulong));
            UInt64 size = BitConverter.ToUInt64(bytes, sizeof(UInt64) + offset);
            return new PadChunk(start, size);
        }

        public bool Equals(PadChunk other)
        {
            return other.Size == Size && other.Start == Start;
        }

        public override bool Equals(object obj)
        {
            PadChunk other = obj as PadChunk;
            return other != null && other.Size == Size && other.Start == Start;
        }

        public override int GetHashCode()
        {
            return Start.GetHashCode() ^ Size.GetHashCode();
        }

        public const int BytesSize = sizeof(UInt64) + sizeof(UInt64);
    }
}
