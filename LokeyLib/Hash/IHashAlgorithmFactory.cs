﻿//***********************************************************************/
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

namespace LokeyLib
{
    public interface IHashAlgorithmFactory
    {
        // Unique ID for the underlying hash algorithm
        uint UID { get; }
        // Unique name for the underlying hash algorithm
        string Name { get; }
        // Generate the underlying hash algorithm
        IHashAlgorithm GenerateAlgorithm();
    }
}
