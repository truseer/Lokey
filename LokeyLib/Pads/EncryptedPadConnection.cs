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

using System.IO;
using System.Text;

namespace LokeyLib
{
    public class EncryptedPadConnection : IPadConnection, IEncryptionPadObject
    {
        public const string DefaultExt = ".econ";

        private FileInfo connectionFile;
        private byte[] iv;
        private byte[] key;
        private IPadDataGenerator rng;

        public string Name { get { return Path.GetFileNameWithoutExtension(connectionFile.Name); } }
        public EncryptedMultiPad From { get; private set; }
        AbstractPad IPadConnection.From { get { return From; } }
        public EncryptedMultiPad To { get; private set; }
        AbstractPad IPadConnection.To { get { return To; } }

        public string ConnectionFilePath { get { return connectionFile.FullName; } }

        public static EncryptedPadConnection Generate(DirectoryInfo rootDir, string name, byte[] key, IPadDataGenerator rng, ulong padSize)
        {
            return Generate(rootDir, name, key, rng, padSize, padSize);
        }

        public static EncryptedPadConnection Generate(DirectoryInfo rootDir, string name, byte[] key, IPadDataGenerator rng, ulong toSize, ulong fromSize, int writeBlockSize = 4096)
        {
            name = name.TrimStart(new char[] { '_' });
            name = name.Replace("\n", "");
            if (writeBlockSize == 0)
                writeBlockSize = 4096;
            FileInfo connFile = new FileInfo(Path.Combine(rootDir.FullName, name + DefaultExt));
            if (connFile.Exists)
                throw new FileOrDirectoryAreadyExistsException("Cannot generate PadConection object with name \""
                    + name + "\" because \"" + connFile.FullName + "\" already exists.");
            string connectionDirectoryPath = Path.Combine(rootDir.FullName, name);
            if (Directory.Exists(connectionDirectoryPath))
                throw new FileOrDirectoryAreadyExistsException("Cannot generate PadConection object with name \""
                    + name + "\" because \"" + connectionDirectoryPath + "\" already exists.");
            EncryptedMultiPad toPad = EncryptedMultiPad.Create(new DirectoryInfo(connectionDirectoryPath), key, rng, "A", toSize, writeBlockSize);
            if (toPad == null)
                throw new CouldNotCreatePadException("Failed to create \"to\" EncryptedMultiPad in \"" + connectionDirectoryPath + "\"");
            EncryptedMultiPad fromPad = EncryptedMultiPad.Create(new DirectoryInfo(connectionDirectoryPath), key, rng, "B", fromSize, writeBlockSize);
            if (fromPad == null)
                throw new CouldNotCreatePadException("Failed to create \"from\" EncryptedMultiPad in \"" + connectionDirectoryPath + "\"");
            return new EncryptedPadConnection(connFile, toPad, fromPad, key, rng.GetPadData(Aes256Ctr.IvSizeBytes), rng);
        }

        public EncryptedPadConnection(FileInfo connectionFile, EncryptedMultiPad toPad, EncryptedMultiPad fromPad, byte[] key, byte[] iv, IPadDataGenerator rng)
        {
            To = toPad;
            From = fromPad;
            this.connectionFile = connectionFile;
            this.key = key;
            this.iv = iv;
            this.rng = rng;
            if (!connectionFile.Exists)
            {
                WriteToFile();
                this.connectionFile = new FileInfo(connectionFile.FullName);
            }
        }

        private void WriteToFile()
        {
            using (FileStream fs = connectionFile.Open(FileMode.Create, FileAccess.Write))
            {
                fs.Write(iv, 0, iv.Length);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (StreamWriter sw = new StreamWriter(fs, Encoding.UTF8))
                    {
                        sw.WriteLine(GetPathRelativeToIndex(To.IndexFilePath));
                        sw.WriteLine(GetPathRelativeToIndex(From.IndexFilePath));
                        byte[] buffer = ms.GetBuffer();
                        Aes256Ctr aes = new Aes256Ctr();
                        buffer = aes.EncryptBytes(key, iv, buffer, true);
                        fs.Write(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        public static EncryptedPadConnection ReadFromFile(FileInfo connectionFile, byte[] key, IPadDataGenerator rng)
        {
            using (FileStream fs = connectionFile.Open(FileMode.Open, FileAccess.Read))
            {
                byte[] iv = new byte[Aes256Ctr.IvSizeBytes];
                int bytesRead = fs.Read(iv, 0, iv.Length);
                if (bytesRead < iv.Length)
                    throw new InvalidEncryptedFileHeaderException("Could not read header from \"" + connectionFile.FullName + "\"");
                byte[] entries = new byte[connectionFile.Length - iv.LongLength];
                bytesRead = fs.Read(entries, 0, entries.Length);
                if (bytesRead < entries.Length)
                    throw new InvalidEncryptedFileHeaderException("Could not read entries from \"" + connectionFile.FullName + "\"");
                entries = new Aes256Ctr().DecryptBytes(key, iv, entries, true);
                using (MemoryStream ms = new MemoryStream(entries))
                {
                    using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                    {
                        string toPadIndexRelativeFilePath = sr.ReadLine();
                        FileInfo toPadIndexFile = new FileInfo(Path.Combine(connectionFile.Directory.FullName, toPadIndexRelativeFilePath));
                        EncryptedMultiPad toPad = new EncryptedMultiPad(toPadIndexFile, key);
                        string fromPadIndexRelativeFilePath = sr.ReadLine();
                        FileInfo fromPadIndexFile = new FileInfo(Path.Combine(connectionFile.Directory.FullName, fromPadIndexRelativeFilePath));
                        EncryptedMultiPad fromPad = new EncryptedMultiPad(fromPadIndexFile, key);
                        return new EncryptedPadConnection(connectionFile, toPad, fromPad, key, iv, rng);
                    }
                }
            }
        }

        IPadConnection IPadConnection.Twin(DirectoryInfo twinRootDir)
        {
            return Twin(twinRootDir);
        }

        public EncryptedPadConnection Twin(DirectoryInfo twinRootDir)
        {
            if (!twinRootDir.Exists)
                twinRootDir.Create();
            FileInfo newConn = new FileInfo(Path.Combine(twinRootDir.FullName, connectionFile.Name));
            EncryptedMultiPad newFrom = To.CopyTo(new FileInfo(Path.Combine(twinRootDir.FullName, GetPathRelativeToIndex(To.IndexFilePath))).Directory, rng);
            EncryptedMultiPad newTo = From.CopyTo(new FileInfo(Path.Combine(twinRootDir.FullName, GetPathRelativeToIndex(From.IndexFilePath))).Directory, rng);
            return new EncryptedPadConnection(newConn, newTo, newFrom, key, iv, rng);
        }

        public void UnsafeDelete()
        {
            From.UnsafeDelete();
            To.UnsafeDelete();
            connectionFile.Delete();
        }

        public void UpdateEncryption(byte[] key)
        {
            UpdateIndexEncryption(key);
            From.UpdateEncryption(key);
            To.UpdateEncryption(key);
        }

        public void UpdateEncryption(byte[] key, IPadDataGenerator rng)
        {
            UpdateIndexEncryption(key, rng.GetPadData(Aes256Ctr.IvSizeBytes));
            From.UpdateEncryption(key, rng);
            To.UpdateEncryption(key, rng);
        }

        private void UpdateIndexEncryption(byte[] key)
        {
            UpdateIndexEncryption(key, iv);
        }

        private void UpdateIndexEncryption(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
            WriteToFile();
        }

        private string GetPathRelativeToIndex(string path)
        {
            return UtilityFunctions.GetRelativePath(connectionFile.FullName, path);
        }
    }
}
