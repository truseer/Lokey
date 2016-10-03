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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LokeyLib
{
    public class PadManagementDirectory : IEncryptionPadObject
    {
        private const string SaltFileName = ".salt";
        private const int SaltSize = 64;

        private DirectoryInfo dir;
        private Dictionary<string, AbstractPad> singlePads;
        private Dictionary<string, IPadConnection> connections;
        private byte[] key;
        private IEnumerable<EncryptedPad> encryptedStandalonePads;
        private IEnumerable<EncryptedPadConnection> encryptedPadConnections;

        public string PadRootPath { get { return dir.FullName; } }
        public IEnumerable<AbstractPad> LonePads { get { return singlePads.Values; } }
        public IEnumerable<string> LonePadIDs { get { return singlePads.Keys; } }
        public IEnumerable<IPadConnection> Connections { get { return connections.Values; } }
        public IEnumerable<string> ConnectionNames { get { return connections.Keys; } }

        public PadManagementDirectory(DirectoryInfo rootDir, IPadDataGenerator rng, string password)
        {
            Initialize(rootDir, rng, password);
        }

        public PadManagementDirectory(DirectoryInfo rootDir, byte[] key = null)
        {
            Initialize(rootDir, new DotNetDefaultPadDataGenerator(), key);
        }

        public PadManagementDirectory(DirectoryInfo rootDir, string password)
        {
            Initialize(rootDir, new DotNetDefaultPadDataGenerator(), password);
        }

        private void Initialize(DirectoryInfo rootDir, IPadDataGenerator rng, string password)
        {
            dir = rootDir;
            Initialize(rootDir, rng, GetKeyFromPassword(password, rng));
        }

        private void Initialize(DirectoryInfo rootDir, IPadDataGenerator rng, byte[] key)
        {
            this.key = key;
            dir = rootDir;
            IEnumerable<AbstractPad> pads = dir.EnumerateFiles("*" + MultiPad.DefaultExt, SearchOption.TopDirectoryOnly)
                .Select(fi => (AbstractPad) new MultiPad(fi))
                .Concat(dir.EnumerateFiles("*" + SimplePadIndex.DefaultExt, SearchOption.TopDirectoryOnly)
                    .Select(fi => Tuple.Create(fi, new FileInfo(Path.ChangeExtension(fi.FullName, SimplePad.DefaultExt))))
                    .Where(simplePadPair => simplePadPair.Item2.Exists)
                    .Select(simplePadPair => new SimplePad(simplePadPair.Item2, simplePadPair.Item1)));
            IEnumerable <IPadConnection> padConnections = dir.EnumerateFiles("*" + PadConnection.DefaultExt, SearchOption.TopDirectoryOnly)
                .Select(connfile => (IPadConnection)PadConnection.ReadFromFile(connfile));
            if (key != null)
            {
                encryptedStandalonePads = dir.EnumerateFiles("*" + EncryptedPad.DefaultExt, SearchOption.TopDirectoryOnly)
                    .Select(fi => EncryptedPad.Load(fi, key));
                pads = pads.Concat(encryptedStandalonePads);
                encryptedPadConnections = dir.EnumerateFiles("*" + EncryptedPadConnection.DefaultExt, SearchOption.TopDirectoryOnly)
                    .Select(fi => EncryptedPadConnection.ReadFromFile(fi, key, rng));
                padConnections = padConnections.Concat(encryptedPadConnections);
            }
            else
            {
                encryptedStandalonePads = new List<EncryptedPad>();
                encryptedPadConnections = new List<EncryptedPadConnection>();
            }
            singlePads = pads.ToDictionary(pad => pad.Identifier);
            connections = padConnections.ToDictionary(conn => conn.Name);
        }

        private byte[] GetKeyFromPassword(string password, IPadDataGenerator rng, bool forceUpdateSalt = false)
        {
            byte[] salt = GetSalt(rng, forceUpdateSalt);
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password), salt, 500000);
            return pbkdf2.GetBytes(Aes256Ctr.KeySizeBytes);
        }

        private byte[] GetSalt(IPadDataGenerator rng, bool forceSaltUpdate = false)
        {
            byte[] salt;
            string saltFilePath = Path.Combine(dir.FullName, SaltFileName);
            if(!forceSaltUpdate && File.Exists(saltFilePath))
            {
                using (FileStream fs = File.Open(saltFilePath, FileMode.Open, FileAccess.Read))
                {
                    salt = new byte[SaltSize];
                    Array.Clear(salt, 0, salt.Length);
                    fs.Read(salt, 0, salt.Length);
                }
            }
            else
            {
                using (FileStream fs = File.Open(saltFilePath, forceSaltUpdate ? FileMode.Create : FileMode.CreateNew, FileAccess.Write))
                {
                    salt = rng.GetPadData(SaltSize);
                    fs.Write(salt, 0, salt.Length);
                }
            }
            return salt;
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

        public void UpdateEncryption(string password, IPadDataGenerator rng, bool updateIVs = true, bool forceUpdateSalt = false)
        {
            byte[] key = GetKeyFromPassword(password, rng, forceUpdateSalt);
            if (updateIVs)
                UpdateEncryption(key, rng);
            else
                UpdateEncryption(key);
        }

        public void UpdateEncryption(byte[] key)
        {
            this.key = key;
            foreach (EncryptedPad epad in encryptedStandalonePads)
                UpdateEncryption(key);
            foreach (EncryptedPadConnection econn in encryptedPadConnections)
                UpdateEncryption(key);
        }

        public void UpdateEncryption(byte[] key, IPadDataGenerator rng)
        {
            this.key = key;
            foreach (EncryptedPad epad in encryptedStandalonePads)
                UpdateEncryption(key, rng);
            foreach (EncryptedPadConnection econn in encryptedPadConnections)
                UpdateEncryption(key, rng);
        }
    }
}
