/***********************************************************************/
// LokeyLib - A library for the management and use of cryptographic pads
/***********************************************************************/
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
/***********************************************************************/

using System;
using System.IO;

namespace LokeyLib
{
    public abstract class AbstractDevPadDataGenerator : IPadDataGenerator
    {
        protected abstract string SourceFilePath { get; }

        public abstract string Name { get; }

        public abstract uint UID { get; }

        public bool AvailableOnPlatform { get { return File.Exists(SourceFilePath); } }

        public byte[] GetPadData(ulong numBytes)
        {
            using (FileStream fs = File.Open(SourceFilePath, FileMode.Open, FileAccess.Read))
            {
                byte[] data = new byte[numBytes];
                ulong bytesRead = 0UL;
                do
                {
                    ulong bytesLeftToRead = numBytes - bytesRead;
                    int bytesToRead = bytesLeftToRead < int.MaxValue ? (int)bytesLeftToRead : int.MaxValue;
                    byte[] bytesThisPass = new byte[bytesToRead];
                    int bytesReadThisPass = 0;
                    do
                    {
                        int bytesReadThisTry = fs.Read(bytesThisPass, bytesReadThisPass, bytesThisPass.Length - bytesReadThisPass);
                        if (bytesReadThisTry <= 0)
                            throw new CouldNotCreatePadException("Could not read from " + SourceFilePath);
                        bytesReadThisPass += bytesReadThisTry;
                    } while (bytesReadThisPass < bytesThisPass.Length);
                    bytesRead += (ulong)bytesReadThisPass;
                    Array.Copy(bytesThisPass, 0L, data, (long)bytesRead, bytesThisPass.LongLength);
                } while (bytesRead < numBytes);
                return data;
            }
        }
    }
}
