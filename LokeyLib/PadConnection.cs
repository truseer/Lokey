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
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace LokeyLib
{
    public class PadConnection
    {
        public const string DefaultExt = ".pcon";

        private FileInfo connectionFile;

        public string Name { get { return Path.GetFileNameWithoutExtension(connectionFile.Name); } }
        public MultiPad From { get; private set; }
        public MultiPad To { get; private set; }
        public string ConnectionFilePath {  get { return connectionFile.FullName; } }

        public static PadConnection Generate(DirectoryInfo rootDir, string name, IPadDataGenerator rng, ulong padSize)
        {
            return Generate(rootDir, name, rng, padSize, padSize);
        }

        public static PadConnection Generate(DirectoryInfo rootDir, string name, IPadDataGenerator rng, ulong toSize, ulong fromSize, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            name = name.TrimStart(new char[] { '_' });
            name = name.Replace("\n", "");
            if (writeBlockSize == 0)
                writeBlockSize = SimplePad.DefaultWriteBlockSize;
            FileInfo connFile = new FileInfo(Path.Combine(rootDir.FullName, name + DefaultExt));
            if (connFile.Exists)
                throw new FileOrDirectoryAreadyExistsException("Cannot generate PadConection object with name \""
                    + name + "\" because \"" + connFile.FullName + "\" already exists.");
            string connectionDirectoryPath = Path.Combine(rootDir.FullName, name);
            if(Directory.Exists(connectionDirectoryPath))
                throw new FileOrDirectoryAreadyExistsException("Cannot generate PadConection object with name \""
                    + name + "\" because \"" + connectionDirectoryPath + "\" already exists.");
            MultiPad toPad = MultiPad.Create(new DirectoryInfo(connectionDirectoryPath), rng, "A", toSize, writeBlockSize);
            if (toPad == null)
                throw new CouldNotCreatePadException("Failed to create \"to\" MultiPad in \"" + connectionDirectoryPath + "\"");
            MultiPad fromPad = MultiPad.Create(new DirectoryInfo(connectionDirectoryPath), rng, "B", fromSize, writeBlockSize);
            if (fromPad == null)
                throw new CouldNotCreatePadException("Failed to create \"from\" MultiPad in \"" + connectionDirectoryPath + "\"");
            return new PadConnection(connFile, toPad, fromPad);
        }

        public PadConnection(FileInfo connectionFile, MultiPad toPad, MultiPad fromPad)
        {
            To = toPad;
            From = fromPad;
            this.connectionFile = connectionFile;
            if (!connectionFile.Exists)
            {
                WriteToFile();
                this.connectionFile = new FileInfo(connectionFile.FullName);
            }
        }

        public void WriteToFile()
        {
            using (FileStream fs = connectionFile.Open(FileMode.Create, FileAccess.Write))
            {
                using (StreamWriter sw = new StreamWriter(fs, Encoding.UTF8))
                {
                    sw.WriteLine(GetPathRelativeToIndex(To.IndexFilePath));
                    sw.WriteLine(GetPathRelativeToIndex(From.IndexFilePath));
                }
            }
        }

        public static PadConnection ReadFromFile(FileInfo connectionFile)
        {
            using (FileStream fs = connectionFile.Open(FileMode.Open, FileAccess.Read))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    string toPadIndexRelativeFilePath = sr.ReadLine();
                    FileInfo toPadIndexFile = new FileInfo(Path.Combine(connectionFile.Directory.FullName, toPadIndexRelativeFilePath));
                    MultiPad toPad = new MultiPad(toPadIndexFile);
                    string fromPadIndexRelativeFilePath = sr.ReadLine();
                    FileInfo fromPadIndexFile = new FileInfo(Path.Combine(connectionFile.Directory.FullName, fromPadIndexRelativeFilePath));
                    MultiPad fromPad = new MultiPad(fromPadIndexFile);
                    return new PadConnection(connectionFile, toPad, fromPad);
                }
            }
        }

        public PadConnection Twin(DirectoryInfo twinRootDir)
        {
            if (!twinRootDir.Exists)
                twinRootDir.Create();
            FileInfo newConn = new FileInfo(Path.Combine(twinRootDir.FullName, connectionFile.Name));
            MultiPad newFrom = To.CopyTo(new FileInfo(Path.Combine(twinRootDir.FullName, GetPathRelativeToIndex(To.IndexFilePath))).Directory);
            MultiPad newTo = From.CopyTo(new FileInfo(Path.Combine(twinRootDir.FullName, GetPathRelativeToIndex(From.IndexFilePath))).Directory);
            return new PadConnection(newConn, newTo, newFrom);
        }

        public void UnsafeDelete()
        {
            From.UnsafeDelete();
            To.UnsafeDelete();
            connectionFile.Delete();
        }

        private string GetPathRelativeToIndex(string path)
        {
            return UtilityFunctions.GetRelativePath(connectionFile.FullName, path);
        }
    }
}
