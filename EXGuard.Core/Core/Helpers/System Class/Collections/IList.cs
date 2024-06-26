﻿// ==++==
// 
//   Copyright (c) Microsoft Corporation.  All rights reserved.
// 
// ==--==
/*============================================================
**
** Interface:  IList
** 
** <OWNER>kimhamil</OWNER>
**
**
** Purpose: Base interface for all Lists.
**
** 
===========================================================*/
namespace EXGuard.Core.Helpers.System.Collections
{
    using global::System;
    using global::System.Collections;

    // An IList is an ordered collection of objects.  The exact ordering
    // is up to the implementation of the list, ranging from a sorted
    // order to insertion order.  
    [global::System.Runtime.InteropServices.ComVisible(true)]
    public interface IList : ICollection
    {
        // The Item property provides methods to read and edit entries in the List.
        Object this[int index]
        {
            get;
            set;
        }

        // Adds an item to the list.  The exact position in the list is 
        // implementation-dependent, so while ArrayList may always insert
        // in the last available location, a SortedList most likely would not.
        // The return value is the position the new element was inserted in.
        int Add(Object value);

        // Returns whether the list contains a particular item.
        bool Contains(Object value);

        // Removes all items from the list.
        void Clear();

        bool IsReadOnly
        { get; }


        bool IsFixedSize
        {
            get;
        }


        // Returns the index of a particular item, if it is in the list.
        // Returns -1 if the item isn't in the list.
        int IndexOf(Object value);

        // Inserts value into the list at position index.
        // index must be non-negative and less than or equal to the 
        // number of elements in the list.  If index equals the number
        // of items in the list, then value is appended to the end.
        void Insert(int index, Object value);

        // Removes an item from the list.
        void Remove(Object value);

        // Removes the item at position index.
        void RemoveAt(int index);
    }
}