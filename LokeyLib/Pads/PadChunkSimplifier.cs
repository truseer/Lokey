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
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    public static class PadChunkSimplifier
    {
        private class PadChunkEnumerableSimplifier : IEnumerable<PadChunk>
        {
            private class PadChunkSimplifierEnumerator : IEnumerator<PadChunk>
            {
                public PadChunkSimplifierEnumerator(List<PadChunk> orderedChunks)
                {
                    iterator = orderedChunks.GetEnumerator();
                    frontChunk = null;
                }
                
                IEnumerator<PadChunk> iterator;
                PadChunk frontChunk;

                private PadChunk GetCurrent()
                {
                    return frontChunk;
                }

                public PadChunk Current
                {
                    get
                    {
                        return GetCurrent();
                    }
                }

                object IEnumerator.Current
                {
                    get
                    {
                        return GetCurrent();
                    }
                }

                public void Dispose() { }

                public bool MoveNext()
                {
                    if (frontChunk == null)
                    {
                        if (!iterator.MoveNext())
                            return false;
                    }
                    frontChunk = iterator.Current;
                    while (iterator.MoveNext() && iterator.Current.Start <= frontChunk.End)
                    {
                        if (frontChunk.End < iterator.Current.End)
                            frontChunk = new PadChunk(frontChunk.Start, iterator.Current.Size + (iterator.Current.Start - frontChunk.Start));
                    }
                    return frontChunk != null;
                }

                public void Reset()
                {
                    iterator.Reset();
                    frontChunk = null;
                }
            }

            public PadChunkEnumerableSimplifier(IEnumerable<PadChunk> chunks)
            {
                this.orderedChunks = chunks.OrderBy(chunk => chunk.Start).ToList();
            }

            private List<PadChunk> orderedChunks;

            private IEnumerator<PadChunk> GenerateEnumerator()
            {
                return new PadChunkSimplifierEnumerator(orderedChunks);
            }

            public IEnumerator<PadChunk> GetEnumerator()
            {
                return GenerateEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GenerateEnumerator();
            }
        }

        public static IEnumerable<PadChunk> Simplify(this IEnumerable<PadChunk> chunks)
        {
            return new PadChunkEnumerableSimplifier(chunks);
        }
    }
}
