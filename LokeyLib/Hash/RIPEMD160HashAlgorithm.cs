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

using System.Security.Cryptography;

namespace LokeyLib
{
    public class RIPEMD160HashAlgorithm : AbstractSystemCryptoHashAlgorithm
    {
        public RIPEMD160HashAlgorithm() : base(new RIPEMD160Managed()) { }

        public override string Name { get { return "RIPEMD-160"; } }

        public override uint UID { get { return 6U; } }

        public static FunctionalHashAlgorithmFactory Factory
        {
            get { return new FunctionalHashAlgorithmFactory(() => new RIPEMD160HashAlgorithm()); }
        }

#if DEBUG
        public static bool RunTest()
        {
            return RunTest(new RIPEMD160HashAlgorithm());
        }

        protected override string ClassName { get { return "RIPEMD160HashAlgorithm"; } }

        protected override AbstractSystemCryptoHashAlgorithm GenerateNewCopy()
        {
            return new RIPEMD160HashAlgorithm();
        }

        protected override HashAlgorithm GenerateUnderlying()
        {
            return new RIPEMD160Managed();
        }
#endif
    }
}
