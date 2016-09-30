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
    public class BufferedEnumerable<T> : IEnumerable<T>
    {
        private class BufferedEnumerator<T> : IEnumerator<T>
        {
            private IEnumerator<T> iterator;
            private CircularBuffer<T> buffer;
            private T currentItem;
            private readonly T[] bufferedStartingItems;

            public BufferedEnumerator(T[] itemsToCache, IEnumerable<T> iterable)
            {
                bufferedStartingItems = itemsToCache;
                iterator = iterable.GetEnumerator();
                buffer = new CircularBuffer<T>(bufferedStartingItems);
                currentItem = default(T);
            }

            public T Current { get { return currentItem; } }

            object IEnumerator.Current { get { return currentItem; } }

            public void Dispose() { iterator.Dispose(); }

            public bool MoveNext()
            {
                if(buffer.Dequeue(out currentItem))
                {
                    if (iterator.MoveNext())
                        buffer.Enqueue(iterator.Current);
                    return true;
                }
                else
                {
                    return false;
                }
            }

            public void Reset()
            {
                iterator.Reset();
                buffer = new CircularBuffer<T>(bufferedStartingItems);
                currentItem = default(T);
            }
        }

        private IEnumerable<T> iterable;
        private T[] bufferedItems;

        public BufferedEnumerable(int itemsToCache, IEnumerable<T> iterable)
        {
            bufferedItems = iterable.Take(itemsToCache).ToArray();
            this.iterable = iterable.Skip(itemsToCache);            
        }

        private IEnumerator<T> GenerateEnumerator() { return new BufferedEnumerator<T>(bufferedItems, iterable); }

        public IEnumerator<T> GetEnumerator() { return GenerateEnumerator(); }

        IEnumerator IEnumerable.GetEnumerator() { return GenerateEnumerator(); }
    }
}
