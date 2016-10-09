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

namespace LokeyLib
{
    public class DevRandomPadDataGenerator : AbstractDevPadDataGenerator
    {
        public override string Name { get { return SourceFilePath; } }

        public override uint UID { get { return 2; } }

        protected override string SourceFilePath { get { return "/dev/random"; } }

#if DEBUG
		public static bool RunTest()
		{
			const string className = "DevRandomPadDataGenerator";
			try
			{
				UtilityFunctions.WriteTestsHeaderFooter(className, true);
				byte[] emptyBits = new byte[16];
				Array.Clear(emptyBits, 0, emptyBits.Length);
				byte[] randomBits = CryptoAlgorithmCache.Instance.GetRNG(2U).GetPadData(16UL);
				return UtilityFunctions.WriteTestResult(className, "/dev/random Read", randomBits.Length == 16 && !UtilityFunctions.ByteArraysEqual(emptyBits, randomBits));
			}
			catch(Exception e)
			{
				UtilityFunctions.WriteTestExceptionFailure (className, e);
				return false;
			}
			finally
			{
				UtilityFunctions.WriteTestsHeaderFooter (className, false);
			}
		}
#endif
    }
}
