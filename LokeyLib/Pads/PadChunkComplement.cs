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

namespace LokeyLib
{
    public static class PadChunkComplement
    {
        private class PadChunkComplementEnumerable : IEnumerable<PadChunk>
        {
            private class PadChunkComplementEnumerator : IEnumerator<PadChunk>
            {
                public PadChunkComplementEnumerator(IEnumerable<PadChunk> simplifiedChunks, UInt64 padSize)
                {
                    chunknumerator = simplifiedChunks.GetEnumerator();
                    this.padSize = padSize;
                    currentChunk = null;
                    unstarted = true;
                    usedChunksFinished = false;
                }

                private bool unstarted;
                private bool usedChunksFinished;
                private IEnumerator<PadChunk> chunknumerator;
                private UInt64 padSize;
                private PadChunk currentChunk;

                public PadChunk Current
                {
                    get
                    {
                        return currentChunk;
                    }
                }

                object IEnumerator.Current
                {
                    get
                    {
                        return currentChunk;
                    }
                }

                public void Dispose() { }

                public bool MoveNext()
                {
                    if(unstarted)
                    {
                        unstarted = false;
                        if(chunknumerator.MoveNext())
                        {
                            if (chunknumerator.Current.Start > 0)
                            {
                                currentChunk = new PadChunk(0, chunknumerator.Current.Start);
                                return true;
                            }
                        }
                        else
                        {
                            usedChunksFinished = true;
                            currentChunk = new PadChunk(0, padSize);
                            return true;
                        }
                    }

                    if (usedChunksFinished)
                    {
                        currentChunk = null;
                        return false;
                    }
                    else
                    {
                        UInt64 currentUsedChunkEnd = chunknumerator.Current.End;
                        if(currentUsedChunkEnd >= padSize)
                        {
                            usedChunksFinished = true;
                            currentChunk = null;
                            return false;
                        }
                        else
                        {
                            if (chunknumerator.MoveNext())
                            {
                                currentChunk = new PadChunk(currentUsedChunkEnd, chunknumerator.Current.Start - currentUsedChunkEnd);
                            }
                            else
                            {
                                usedChunksFinished = true;
                                currentChunk = new PadChunk(currentUsedChunkEnd, padSize - currentUsedChunkEnd);
                            }
                            return true;
                        }
                    }
                }

                public void Reset()
                {
                    chunknumerator.Reset();
                    currentChunk = null;
                    unstarted = true;
                    usedChunksFinished = false;
                }
            }

            public PadChunkComplementEnumerable(IEnumerable<PadChunk> chunks, UInt64 padSize)
            {
                this.simplifiedChunks = chunks.Simplify();
                this.padSize = padSize;
            }

            private IEnumerable<PadChunk> simplifiedChunks;
            private UInt64 padSize;

            public IEnumerator<PadChunk> GetEnumerator()
            {
                return GenerateEnumerator();
            }

            private IEnumerator<PadChunk> GenerateEnumerator()
            {
                return new PadChunkComplementEnumerator(simplifiedChunks, padSize);
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GenerateEnumerator();
            }
        }

        public static IEnumerable<PadChunk> Complement(this IEnumerable<PadChunk> chunks, UInt64 padSize)
        {
            return new PadChunkComplementEnumerable(chunks, padSize);
        }
    }
}
