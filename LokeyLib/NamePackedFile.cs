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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    public class NamePackedFile
    {
        public const string FileNamePackedExt = ".nmls";

        private FileInfo file;

        public NamePackedFile(string filePath)
        {
            file = new FileInfo(filePath);
            FileNameIsPacked = file.Extension.Equals(FileNamePackedExt);
        }

        public string FilePath { get { return file.FullName; } }

        public bool FileNameIsPacked { get; private set; }

        /************************************************
        | Footer appended to the encrypted file.        |
        *************************************************
        | Description                    | Size (Bytes) |
        *************************************************
        | File Name String               | N            |
        | File Name Start Location       | 8            |
        ************************************************/

        public void PackFileName()
        {
            if (!FileNameIsPacked)
            {
                using (FileStream fs = file.Open(FileMode.Append, FileAccess.Write))
                {
                    long position = fs.Position;
                    byte[] fileNameBytes = Encoding.UTF8.GetBytes(file.Name);
                    byte[] positonBytes = BitConverter.GetBytes(position);
                    UtilityFunctions.EndianSwap(positonBytes);
                    fs.Write(fileNameBytes, 0, fileNameBytes.Length);
                    fs.Write(positonBytes, 0, positonBytes.Length);
                }
                FileInfo fi = new FileInfo(file.FullName);
                string newPath = Path.Combine(fi.DirectoryName, Path.GetRandomFileName().Replace(".", "") + FileNamePackedExt);
                fi.MoveTo(newPath);
                file = new FileInfo(newPath);
                FileNameIsPacked = true;
            }
        }

        public void UnpackFileName()
        {
            if (FileNameIsPacked)
            {
                string fileName = null;
                using (FileStream fs = file.Open(FileMode.Open, FileAccess.ReadWrite))
                {
                    byte[] stringPositionBytes = new byte[sizeof(long)];
                    fs.Seek(-sizeof(long), SeekOrigin.End);
                    int bytesRead = fs.Read(stringPositionBytes, 0, stringPositionBytes.Length);
                    if (bytesRead == stringPositionBytes.Length)
                    {
                        UtilityFunctions.EndianSwap(stringPositionBytes);
                        long stringPosition = BitConverter.ToInt64(stringPositionBytes, 0);
                        fs.Position = stringPosition;
                        long stringBufferLength = (fs.Length - stringPosition) - sizeof(long);
                        byte[] stringBuffer = new byte[stringBufferLength];
                        int fileNameBytesRead = fs.Read(stringBuffer, 0, stringBuffer.Length);
                        if (fileNameBytesRead == stringBufferLength)
                        {
                            fileName = Encoding.UTF8.GetString(stringBuffer);
                            fs.SetLength(stringPosition);
                        }
                    }
                }
                if (fileName != null)
                {
                    FileInfo fi = new FileInfo(file.FullName);
                    string newPath = Path.Combine(file.DirectoryName, fileName);
                    fi.MoveTo(newPath);
                    file = new FileInfo(newPath);
                    FileNameIsPacked = false;
                }
            }
        }

#if DEBUG
        private const string ClassName = "NamePackedFile";

        public static bool RunTest()
        {
            UtilityFunctions.WriteTestsHeaderFooter(ClassName, true);
            FileInfo testFile = null, testFile2 = null;
            try
            {
                bool testsSucceeded = true;
                testFile = UtilityFunctions.GenerateTestPlaintextFile("test.bin", 1 << 10);
                string testFile2Name = "test2.bin";
                testFile2 = testFile.CopyTo(testFile2Name);
                NamePackedFile nmls = new NamePackedFile(testFile2.FullName);
                nmls.PackFileName();
                testFile2 = new FileInfo(nmls.FilePath);
                testsSucceeded &= WriteTestResult("Name Packing", !testFile2.Name.Equals(testFile2Name));
                nmls.UnpackFileName();
                testFile2 = new FileInfo(nmls.FilePath);
                testsSucceeded &= WriteTestResult("Name Unpacking", testFile2.Name.Equals(testFile2Name));
                testsSucceeded &= WriteTestResult("File Integrity", UtilityFunctions.FilesEqual(testFile, testFile2));
                return testsSucceeded;
            }
            catch (Exception e)
            {
                UtilityFunctions.WriteTestExceptionFailure(ClassName, e);
                return false;
            }
            finally
            {
                UtilityFunctions.WriteTestsHeaderFooter(ClassName, false);
                if (testFile != null) testFile.Delete();
                if (testFile2 != null) testFile2.Delete();
            }
        }

        private static bool WriteTestResult(string testName, bool success)
        {
            return UtilityFunctions.WriteTestResult(ClassName, testName, success);
        }
#endif
    }
}
