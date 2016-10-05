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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    public class SimplePadIndex : IFileComponentListable
    {
        public const string DefaultExt = ".sidx";

        public static SimplePadIndex Create(FileInfo indexFile)
        {
            if (indexFile.Exists)
                return null;
            using (FileStream fs = indexFile.Create()) { }
            return new SimplePadIndex(indexFile);
        }

        public SimplePadIndex(FileInfo indexFile)
        {
            index = indexFile;
            usedChunks = new List<PadChunk>();
            ReadChunkList();
        }

        private FileInfo index;
        private List<PadChunk> usedChunks;

        public FileInfo IndexFileInfo { get { return index; } }

        public SimplePadIndex CopyTo(DirectoryInfo dir)
        {
            if (!dir.Exists)
                dir.Create();
            return new SimplePadIndex(index.CopyTo(Path.Combine(dir.FullName, index.Name)));
        }

        public bool IsValid { get { return index.Exists; } }

        public IEnumerable<FileInfo> ComponentFiles { get { return new FileInfo[] { index }; } }

        public IEnumerable<PadChunk> GenerateUnusedChunks(UInt64 padSize)
        {
            return usedChunks.Complement(padSize);
        }

        public void Update(PadChunk usedChunk)
        {
            usedChunks.Add(usedChunk);
            WriteChunkList();
        }

        public void Clear()
        {
            usedChunks.Clear();
            WriteChunkList();
        }

        private void SimplifyChunkList()
        {
            if(usedChunks.Count > 1)
            {
                usedChunks = usedChunks.Simplify().ToList();
            }
        }

        private void WriteChunkList()
        {
            SimplifyChunkList();
            using (FileStream fs = index.Open(FileMode.Truncate, FileAccess.Write))
            {
                foreach (PadChunk chunk in usedChunks)
                {
                    byte[] chunkBytes = chunk.ToBytes();
                    fs.Write(chunkBytes, 0, chunkBytes.Length);
                }
            }
        }

        private void ReadChunkList()
        {
            usedChunks.Clear();
            using (FileStream fs = index.Open(FileMode.Open, FileAccess.Read))
            {
                byte[] padChunkBuf = new byte[PadChunk.BytesSize];
                while (fs.Read(padChunkBuf, 0, padChunkBuf.Length) > 0)
                {
                    usedChunks.Add(PadChunk.FromBytes(padChunkBuf));
                }
            }
            SimplifyChunkList();
        }
    }
}
