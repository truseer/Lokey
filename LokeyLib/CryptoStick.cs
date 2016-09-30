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
    public class CryptoStick
    {
        public static IEnumerable<DriveInfo> RemovableDrives
        {
            get
            {
				List<DriveInfo> drives = DriveInfo.GetDrives ().ToList();
				return drives.Where (drive => drive.DriveType == DriveType.Removable
					|| (drive.DriveType == DriveType.Fixed
						&& (drive.RootDirectory.FullName.StartsWith("/media/")
							|| drive.RootDirectory.FullName.StartsWith("/mnt/"))));
            }
        }

        private DriveInfo drive;
        public DirectoryInfo Dir { get; }
        public PadManagementDirectory Manager { get; }

        public CryptoStick(DriveInfo drive)
        {
            this.drive = drive;
            Dir = drive.RootDirectory;
            Manager = new PadManagementDirectory(Dir);
        }

        public CryptoStick(DriveInfo drive, string subpath)
        {
            this.drive = drive;
            Dir = new DirectoryInfo(Path.Combine(drive.RootDirectory.FullName, subpath));
            Manager = new PadManagementDirectory(Dir);
        }

        public CryptoStick(DirectoryInfo padManagementDir)
        {
            Dir = padManagementDir;
            drive = new DriveInfo(padManagementDir.Root.FullName.Substring(0, 1));
            Manager = new PadManagementDirectory(Dir);
        }

        public bool IsReady { get { return drive.IsReady; } }

        public PadConnection GenerateMaximumConnection(string connectionName, IPadDataGenerator rng)
        {
            long freeSpace = drive.AvailableFreeSpace;
            ulong padSize = ((ulong)freeSpace - (1UL << 22)) / 2UL;
            return Manager.GenerateConnection(connectionName, rng, padSize);
        }

        public AbstractPad GenerateMaximumPad(string padName, IPadDataGenerator rng)
        {
            long freeSpace = drive.AvailableFreeSpace;
            ulong padSize = ((ulong)freeSpace - (1UL << 23)) / 2UL;
            return Manager.GenerateLonePad(padName, rng, padSize);
        }

#if DEBUG
        private const string ClassName = "CryptoStick";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            try
            {
                bool testsSucceeded = true;
                IEnumerable<DriveInfo> removables = RemovableDrives;
                DriveInfo stickDrive = removables.First();
                CryptoStick stick = new CryptoStick(stickDrive);
                PadConnection connection = stick.GenerateMaximumConnection(Path.GetRandomFileName().Replace(".", ""), CryptoAlgorithmCache.Instance.GetRNG(1));

                DriveInfo secondStickDrive = removables.Skip(1).First();
                DirectoryInfo secondStickRootDir = secondStickDrive.RootDirectory;
                PadConnection twinnedConnection = connection.Twin(secondStickRootDir);

                FileInfo ptTest = UtilityFunctions.GenerateTestPlaintextFile("test.bin", 1 << 21);
                try
                {
                    foreach (ICryptoAlgorithmFactory cf in CryptoAlgorithmCache.Instance.Algorithms)
                    {
                        FileInfo fileCopy = ptTest.CopyTo("testcopy.bin");
                        try
                        {
                            FileInfo fileCopy2 = ptTest.CopyTo("testcopy2.bin");
                            try
                            {
                                {
                                    EncryptedFile pt = EncryptedFile.CreateFromPlaintextFile(fileCopy, connection, cf);
                                    pt.Encrypt();
                                    fileCopy = new FileInfo(fileCopy.FullName);
                                }
                                FileInfo ciphertextCopy = fileCopy.CopyTo("testcopy.bin.ct");
                                try
                                {
                                    {
                                        EncryptedFile pt2 = EncryptedFile.CreateFromPlaintextFile(fileCopy2, twinnedConnection, cf);
                                        pt2.Encrypt();
                                        fileCopy2 = new FileInfo(fileCopy2.FullName);
                                    }
                                    FileInfo ciphertextCopy2 = fileCopy2.CopyTo("testcopy2.bin.ct");
                                    try
                                    {
                                        {
                                            EncryptedFile ct = EncryptedFile.CreateFromEncryptedFile(ciphertextCopy, twinnedConnection);
                                            ct.Decrypt();
                                            ciphertextCopy = new FileInfo(ciphertextCopy.FullName);
                                            testsSucceeded &= WriteTestResult(cf.Name + " File Encryption/Decryption Connection", UtilityFunctions.FilesEqual(ptTest, ciphertextCopy));
                                        }
                                        {
                                            EncryptedFile ct2 = EncryptedFile.CreateFromEncryptedFile(ciphertextCopy2, connection);
                                            ct2.Decrypt();
                                            ciphertextCopy2 = new FileInfo(ciphertextCopy2.FullName);
                                            testsSucceeded &= WriteTestResult(cf.Name + " File Encryption/Decryption Twinned Connection", UtilityFunctions.FilesEqual(ptTest, ciphertextCopy2));
                                        }
                                    }
                                    finally { ciphertextCopy2.Delete(); }
                                }
                                finally { ciphertextCopy.Delete(); }
                            }
                            finally { fileCopy2.Delete(); }
                        }
                        finally { fileCopy.Delete(); }
                    }
                    return testsSucceeded;
                }
                finally { ptTest.Delete(); }
            }
            catch(Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                UtilityFunctions.WriteTestsHeaderFooter(ClassName, false);
            }
        }

        private static bool WriteTestResult(string testName, bool success)
        {
            return UtilityFunctions.WriteTestResult(ClassName, testName, success);
        }
#endif
            }
}
