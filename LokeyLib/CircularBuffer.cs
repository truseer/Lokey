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
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LokeyLib
{
    internal class CircularBuffer<T>
    {
        private T[] items;
        uint front;
        uint back;
        int numItems;

        public CircularBuffer(uint capacity)
        {
            items = new T[capacity];
            front = 0U;
            back = 0U;
            numItems = 0;
        }

        public CircularBuffer(T[] startingItems)
        {
            items = new T[startingItems.Length];
            Array.Copy(startingItems, items, startingItems.Length);
            front = 0U;
            back = 0U;
            numItems = startingItems.Length;
        }

        public void Clear()
        {
            front = 0U;
            back = 0U;
            numItems = 0;
            for (int i = 0; i < items.Length; ++i) items[i] = default(T);
        }

        public bool Enqueue(T item)
        {
            if (numItems < items.Length)
            {
                items[back++] = item;
                ++numItems;
                if (back >= items.Length)
                    back = 0;
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool Dequeue(out T val)
        {
            if (numItems > 0)
            {
                val = items[front++];
                --numItems;
                if (front >= items.Length)
                    front = 0;
                return true;
            }
            else
            {
                val = default(T);
                return false;
            }
        }
    }
}
