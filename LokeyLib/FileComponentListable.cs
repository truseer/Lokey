//**********************************************************************/
// LokeyLib - A library for the management and use of cryptographic pads
//**********************************************************************/
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
//**********************************************************************/

using System.IO;

namespace LokeyLib
{
    public static class FileComponentListable
    {
        public static void NonsecureDelete(this IFileComponentListable listable)
        {
            foreach (FileInfo file in listable.ComponentFiles)
            {
                file.Delete();
            }
        }

        public static void SecureDelete(this IFileComponentListable listable, IPadDataGenerator rng, int chunkSize = 4096)
        {
            byte[] chunkBytes = new byte[chunkSize];
            foreach (FileInfo file in listable.ComponentFiles)
            {
                long fileSize = file.Length;
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.Write))
                {
                    long chunks = fileSize / chunkSize;
                    for(long chunk = 0L; chunk < chunks; ++chunk)
                    {
                        rng.GetPadData(chunkBytes);
                        fs.Write(chunkBytes, 0, chunkSize);
                    }
                    long bytesWritten = chunks * chunkSize;
                    int bytesLeft = (int)(fileSize - bytesWritten);
                    if(bytesLeft > 0)
                    {
                        chunkBytes = rng.GetPadData((ulong)bytesLeft);
                        fs.Write(chunkBytes, 0, chunkBytes.Length);
                    }
                }
                file.Delete();
            }
        }
    }
}
