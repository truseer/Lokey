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

﻿#define USE_RANDOM_BUFFER_TEST

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace LokeyLib
{
    public class CryptoAlgorithmCache
    {
        private static CryptoAlgorithmCache _instance = new CryptoAlgorithmCache();
        public static CryptoAlgorithmCache Instance { get { return _instance; } }

        public CryptoAlgorithmCache()
        {
            // Add Encryption Algorithms
            // Add(new NoEncryptionAlgorithmFactory());
            Add(new OneTimePadAlgorithmFactory());
            ICryptoAlgorithmFactory defaultAlg = new Aes256CbcPadIvAlgorithmFactory();
            Add(defaultAlg);
            Add(new Aes256EcbPadIvAlgorithmFactory());
            Add(new Aes256CtrPadIvAlgorithmFactory());
            Add(new AesCtrFactory(AesBlockCipher.AesKeyLength._128Bits));
            Add(new AesCtrFactory(AesBlockCipher.AesKeyLength._192Bits));
            Add(new AesCtrFactory(AesBlockCipher.AesKeyLength._256Bits));

            // Add Pad Generators
            IPadDataGenerator defaultRng = new DotNetDefaultPadDataGenerator();
            Add(defaultRng);
            DevRandomPadDataGenerator devRandom = new DevRandomPadDataGenerator();
            if (devRandom.AvailableOnPlatform)
                Add(devRandom);
			DevUrandomPadDataGenerator devUrandom = new DevUrandomPadDataGenerator();
			if (devUrandom.AvailableOnPlatform)
				Add(devUrandom);

            // Add Hash Algorithms
            Add(MD5HashAlgorthm.Factory);
            Add(SHA1HashAlgorithm.Factory);
            Add(SHA256HashAlgorithm.Factory);
            Add(SHA384HashAlgorithm.Factory);
            Add(RIPEMD160HashAlgorithm.Factory);
            IHashAlgorithmFactory sha512 = SHA512HashAlgorithm.Factory;
            Add(sha512);

            DefaultRNG = defaultRng;
            DefaultCryptoAlgorithm = defaultAlg;
            DefaultHashAlgorithm = sha512;
        }

        private Dictionary<UInt32, ICryptoAlgorithmFactory> algorithms = new Dictionary<uint, ICryptoAlgorithmFactory>();
        private Dictionary<string, ICryptoAlgorithmFactory> algorithmsByName = new Dictionary<string, ICryptoAlgorithmFactory>();
        private Dictionary<UInt32, IPadDataGenerator> rngs = new Dictionary<uint, IPadDataGenerator>();
        private Dictionary<string, IPadDataGenerator> rngsByName = new Dictionary<string, IPadDataGenerator>();
        private Dictionary<uint, IHashAlgorithmFactory> hashAlgs = new Dictionary<uint, IHashAlgorithmFactory>();
        private Dictionary<string, IHashAlgorithmFactory> hashAlgsByName = new Dictionary<string, IHashAlgorithmFactory>();
        private Dictionary<uint, IStreamCipher> streamCiphers = new Dictionary<uint, IStreamCipher>();
        private Dictionary<uint, IStreamCipher> streamCiphersByName = new Dictionary<uint, IStreamCipher>();

        public IPadDataGenerator DefaultRNG { get; private set; }
        public ICryptoAlgorithmFactory DefaultCryptoAlgorithm { get; private set; }
        public IHashAlgorithmFactory DefaultHashAlgorithm { get; private set; }

        public void Add(IHashAlgorithmFactory hashFactory)
        {
            hashAlgs.Add(hashFactory.UID, hashFactory);
            hashAlgsByName.Add(hashFactory.Name, hashFactory);
        }

        public void Add(ICryptoAlgorithmFactory algorithm)
        {
            algorithms.Add(algorithm.UID, algorithm);
            algorithmsByName.Add(algorithm.Name.ToLowerInvariant(), algorithm);
        }

        public void Add(IPadDataGenerator rng)
        {
            rngs.Add(rng.UID, rng);
            rngsByName.Add(rng.Name.ToLowerInvariant(), rng);
        }

        public ICollection<ICryptoAlgorithmFactory> Algorithms { get { return algorithms.Values; } }

        public ICollection<IPadDataGenerator> RNGs { get { return rngs.Values; } }

        public ICollection<IHashAlgorithmFactory> HashAlgorithms { get { return hashAlgs.Values; } }

        public ICryptoAlgorithmFactory GetAlgorithm(UInt32 uid)
        {
            return algorithms[uid];
        }

        public ICryptoAlgorithmFactory GetAlgorithm(string name)
        {
            return algorithmsByName[name.ToLowerInvariant()];
        }

        public void SetDefaultCryptoAlgorithm(UInt32 uid)
        {
            DefaultCryptoAlgorithm = GetAlgorithm(uid);
        }

        public void SetDefaultCryptoAlgorithm(string name)
        {
            DefaultCryptoAlgorithm = GetAlgorithm(name);
        }

        public IPadDataGenerator GetRNG(UInt32 uid)
        {
            return rngs[uid];
        }

        public IPadDataGenerator GetRNG(string name)
        {
            return rngsByName[name.ToLowerInvariant()];
        }

        public void SetDefaultRNG(UInt32 uid)
        {
            DefaultRNG = GetRNG(uid);
        }

        public void SetDefaultRNG(string name)
        {
            DefaultRNG = GetRNG(name);
        }

        public IHashAlgorithmFactory GetHashAlgorithm(uint uid)
        {
            return hashAlgs[uid];
        }

        public IHashAlgorithmFactory GetHashAlgorithm(string name)
        {
            return hashAlgsByName[name];
        }

        public void SetDefaultHashAlgorithm(uint uid)
        {
            DefaultHashAlgorithm = GetHashAlgorithm(uid);
        }

        public void SetDefaultHashAlgorithm(string name)
        {
            DefaultHashAlgorithm = GetHashAlgorithm(name);
        }

#if DEBUG
        private const string ClassName = "CryptoAlgorithmCache";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            SimplePad pad = null;
            try
            {
                bool testsSucceeded = true;
                Random testRand = new Random();
                foreach (IPadDataGenerator rng in Instance.RNGs)
                {
                    UtilityFunctions.WriteTestsHeaderFooter(rng.Name, true);
                    int bytesSize = testRand.Next(64, 4096 * 2);
                    byte[] a = rng.GetPadData((ulong)bytesSize);
                    byte[] b = rng.GetPadData((ulong)bytesSize);
                    testsSucceeded &= UtilityFunctions.WriteTestResult(rng.Name, "Byte Grab", a.Length == b.Length && !UtilityFunctions.ByteArraysEqual(a, b));
                    UtilityFunctions.WriteTestsHeaderFooter(rng.Name, false);
                }
                pad = SimplePad.Create(new FileInfo("test" + SimplePad.DefaultExt), new FileInfo("test" + SimplePadIndex.DefaultExt));
                foreach (ICryptoAlgorithmFactory f in Instance.Algorithms)
                {
                    UtilityFunctions.WriteTestsHeaderFooter(f.Name, true);
                    ICryptoAlgorithm alg = f.GenerateCryptoAlgorithm();
                    testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Name", f.Name.Equals(alg.Name));
                    testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "UID", f.UID == alg.UID);
                    {
                        int bytesSize = testRand.Next(64, 4096 * 2);
                        byte[] ptIn = new byte[bytesSize];
                        testRand.NextBytes(ptIn);
                        ulong keySize = alg.GetKeySize((ulong)ptIn.Length);
                        pad.TruncateWriteBytes(Instance.GetRNG(1), keySize * 2);
                        PadChunk keyChunk = new PadChunk((ulong)testRand.Next((int)keySize), keySize);
                        byte[] ctOut = alg.Encrypt(pad, keyChunk, ptIn);
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Encryption", (f.UID != 0) ^ UtilityFunctions.ByteArraysEqual(ptIn, ctOut));
                        byte[] ptOut = alg.Decrypt(pad, keyChunk, ctOut);
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Decryption", UtilityFunctions.ByteArraysEqual(ptIn, ptOut));
                    }
                    {
#if USE_RANDOM_BUFFER_TEST
                        int numChunks = testRand.Next(10, 32);
                        int chunkBlocks = testRand.Next(2, 32);
#else
                        int numChunks = 10;
                        int chunkBlocks = 2;
                        int fillVal = 0;
#endif
                        byte[][] ptChunks = new byte[numChunks + 1][];
                        for (int i = 0; i < numChunks; ++i)
                        {
                            ptChunks[i] = new byte[chunkBlocks * alg.BlockSize];
#if USE_RANDOM_BUFFER_TEST
                            testRand.NextBytes(ptChunks[i]);
#else
                            for (int j = 0; j < ptChunks[i].Length; ++j) ptChunks[i][j] = (byte)(fillVal++ % 256);
#endif
                        }
                        int finalChunkSize = testRand.Next(chunkBlocks * alg.BlockSize);
                        ptChunks[numChunks] = new byte[finalChunkSize];
#if USE_RANDOM_BUFFER_TEST
                        testRand.NextBytes(ptChunks[numChunks]);
#else
                        for (int j = 0; j < ptChunks[numChunks].Length; ++j) ptChunks[numChunks][j] = (byte)(fillVal++ % 256);
#endif
                        int totalSize = (numChunks * chunkBlocks * alg.BlockSize) + finalChunkSize;
                        ulong keySize = alg.GetKeySize((ulong)totalSize);
                        pad.TruncateWriteBytes(Instance.GetRNG(1), keySize * 2);
                        PadChunk keyChunk = new PadChunk((ulong)testRand.Next((int)keySize), keySize);
                        byte[][] ctChunks = alg.Encrypt(pad, keyChunk, ptChunks).ToArray();
                        byte[] ctChunkBlock = ctChunks.SelectMany(a => a).ToArray();
                        byte[] ptBlock = ptChunks.SelectMany(a => a).ToArray();
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Encryption Iterator",
                            (f.UID != 0) ^ UtilityFunctions.ByteArraysEqual(ptBlock, ctChunkBlock));
                        byte[] ctBlock = alg.Encrypt(pad, keyChunk, ptBlock);
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Encryption Iterator Equivalence",
                            UtilityFunctions.ByteArraysEqual(ctBlock, ctChunkBlock));
                        byte[][] ptOutChunks = alg.Decrypt(pad, keyChunk, ctChunks).ToArray();
                        byte[] ptOutChunksBlock = ptOutChunks.SelectMany(a => a).ToArray();
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Decryption Iterator",
                            UtilityFunctions.ByteArraysEqual(ptBlock, ptOutChunksBlock));
                        byte[] ctChunkBlockDecrypted = alg.Decrypt(pad, keyChunk, ctChunkBlock);
                        testsSucceeded &= UtilityFunctions.WriteTestResult(f.Name, "Decryption Iterator Equivalence",
                            UtilityFunctions.ByteArraysEqual(ctChunkBlockDecrypted, ptOutChunksBlock));
                    }
                    UtilityFunctions.WriteTestsHeaderFooter(f.Name, false);
                }
                return testsSucceeded;
            }
            catch (Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                if (pad != null)
                {
                    try { pad.NonsecureDelete(); }
                    catch (Exception e) { UtilityFunctions.WriteTestExceptionFailure(ClassName, e); }
                }
                UtilityFunctions.WriteTestsHeaderFooter(ClassName, false);
            }
        }
#endif
    }
}
