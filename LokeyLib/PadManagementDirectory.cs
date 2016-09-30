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

namespace LokeyLib
{
    public class PadManagementDirectory
    {
        private DirectoryInfo dir;
        private Dictionary<string, AbstractPad> singlePads;
        private Dictionary<string, PadConnection> connections;

        public string PadRootPath { get { return dir.FullName; } }
        public IEnumerable<AbstractPad> LonePads { get { return singlePads.Values; } }
        public IEnumerable<string> LonePadIDs { get { return singlePads.Keys; } }
        public IEnumerable<PadConnection> Connections { get { return connections.Values; } }
        public IEnumerable<string> ConnectionNames { get { return connections.Keys; } }

        public PadManagementDirectory(DirectoryInfo rootDir)
        {
            dir = rootDir;
            singlePads = dir.EnumerateFiles("*" + MultiPad.DefaultExt, SearchOption.TopDirectoryOnly)
                .Select(fi => (AbstractPad) new MultiPad(fi))
                .Concat(dir.EnumerateFiles("*" + SimplePadIndex.DefaultExt, SearchOption.TopDirectoryOnly)
                    .Select(fi => Tuple.Create(fi, new FileInfo(Path.ChangeExtension(fi.FullName, SimplePad.DefaultExt))))
                    .Where(simplePadPair => simplePadPair.Item2.Exists)
                    .Select(simplePadPair => new SimplePad(simplePadPair.Item2, simplePadPair.Item1)))
                .ToDictionary(pad => pad.Identifier);
            connections = dir.EnumerateFiles("*" + PadConnection.DefaultExt, SearchOption.TopDirectoryOnly)
                .Select(connfile => PadConnection.ReadFromFile(connfile))
                .ToDictionary(conn => conn.Name);
        }

        public void EncryptFileFromPad(string padId, FileInfo file, ICryptoAlgorithmFactory alg, int blockSize)
        {
            EncryptedFile.CreateFromPlaintextFile(file, singlePads[padId], alg).Encrypt(blockSize);
        }

        public void EncryptFileFromConnection(string connectionName, FileInfo file, ICryptoAlgorithmFactory alg, int blockSize)
        {
            EncryptedFile.CreateFromPlaintextFile(file, connections[connectionName], alg).Encrypt(blockSize);
        }

        public void DecryptFileFromPad(string padId, FileInfo file, int blockSize)
        {
            EncryptedFile.CreateFromEncryptedFile(file, singlePads[padId]).Decrypt(blockSize);
        }

        public void DecryptFileFromConnection(string connectionName, FileInfo file, int blockSize)
        {
            EncryptedFile.CreateFromEncryptedFile(file, connections[connectionName]).Decrypt(blockSize);
        }

        public PadConnection GenerateConnection(string name, IPadDataGenerator rng, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            return GenerateConnection(name, rng, size, size, writeBlockSize);
        }

        public PadConnection GenerateConnection(string name, IPadDataGenerator rng, ulong toSize, ulong fromSize, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            PadConnection conn = PadConnection.Generate(dir, name, rng, toSize, fromSize, writeBlockSize);
            connections.Add(conn.Name, conn);
            return conn;
        }

        public SimplePad GenerateSimplePad(string name, IPadDataGenerator rng, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            SimplePad pad = SimplePad.Create(
                new FileInfo(Path.Combine(dir.FullName, name + SimplePad.DefaultExt)),
                new FileInfo(Path.Combine(dir.FullName, name + SimplePadIndex.DefaultExt)),
                rng, size, writeBlockSize);
            singlePads.Add(pad.Identifier, pad);
            return pad;
        }

        public MultiPad GenerateMultiPad(string name, IPadDataGenerator rng, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            MultiPad pad = MultiPad.Create(dir, new DirectoryInfo(Path.Combine(dir.FullName, name)), rng, name, size, writeBlockSize);
            singlePads.Add(pad.Identifier, pad);
            return pad;
        }

        public AbstractPad GenerateLonePad(string name, IPadDataGenerator rng, ulong size, int writeBlockSize = SimplePad.DefaultWriteBlockSize)
        {
            return (size > int.MaxValue)
                ? (AbstractPad)GenerateMultiPad(name, rng, size, writeBlockSize)
                : (AbstractPad)GenerateSimplePad(name, rng, size, writeBlockSize);
        }
    }
}
