﻿namespace EXGuard.Core.Helpers.System.Collections.Generic
{

    /// <summary>
    /// ABOUT:
    /// Helps with operations that rely on bit marking to indicate whether an item in the 
    /// collection should be added, removed, visited already, etc. 
    /// 
    /// BitHelper doesn't allocate the array; you must pass in an array or ints allocated on the 
    /// stack or heap. ToIntArrayLength() tells you the int array size you must allocate. 
    /// 
    /// USAGE:
    /// Suppose you need to represent a bit array of length (i.e. logical bit array length)
    /// BIT_ARRAY_LENGTH. Then this is the suggested way to instantiate BitHelper:
    /// ***************************************************************************
    /// int intArrayLength = BitHelper.ToIntArrayLength(BIT_ARRAY_LENGTH);
    /// BitHelper bitHelper;
    /// if (intArrayLength less than stack alloc threshold)
    ///     int* m_arrayPtr = stackalloc int[intArrayLength];
    ///     bitHelper = new BitHelper(m_arrayPtr, intArrayLength);
    /// else
    ///     int[] m_arrayPtr = new int[intArrayLength];
    ///     bitHelper = new BitHelper(m_arrayPtr, intArrayLength);
    /// ***************************************************************************
    /// 
    /// IMPORTANT:
    /// The second ctor args, length, should be specified as the length of the int array, not
    /// the logical bit array. Because length is used for bounds checking into the int array,
    /// it's especially important to get this correct for the stackalloc version. See the code 
    /// samples above; this is the value gotten from ToIntArrayLength(). 
    /// 
    /// The length ctor argument is the only exception; for other methods -- MarkBit and 
    /// IsMarked -- pass in values as indices into the logical bit array, and it will be mapped
    /// to the position within the array of ints.
    /// 
    /// 

    unsafe internal class BitHelper
    {   // should not be serialized

        private const byte MarkedBitFlag = 1;
        private const byte IntSize = 32;

        // m_length of underlying int array (not logical bit array)
        private int m_length;

        // ptr to stack alloc'd array of ints
        [global::System.Security.SecurityCritical]
        private int* m_arrayPtr;

        // array of ints
        private int[] m_array;

        // whether to operate on stack alloc'd or heap alloc'd array 
        private bool useStackAlloc;

        /// <summary>
        /// Instantiates a BitHelper with a heap alloc'd array of ints
        /// </summary>
        /// <param name="bitArray">int array to hold bits</param>
        /// <param name="length">length of int array</param>
        [global::System.Security.SecurityCritical]
        internal BitHelper(int* bitArrayPtr, int length)
        {
            this.m_arrayPtr = bitArrayPtr;
            this.m_length = length;
            useStackAlloc = true;
        }

        /// <summary>
        /// Instantiates a BitHelper with a heap alloc'd array of ints
        /// </summary>
        /// <param name="bitArray">int array to hold bits</param>
        /// <param name="length">length of int array</param>
        internal BitHelper(int[] bitArray, int length)
        {
            this.m_array = bitArray;
            this.m_length = length;
        }

        /// <summary>
        /// Mark bit at specified position
        /// </summary>
        /// <param name="bitPosition"></param>
        [global::System.Security.SecuritySafeCritical]
        internal unsafe void MarkBit(int bitPosition)
        {
            if (useStackAlloc)
            {
                int bitArrayIndex = bitPosition / IntSize;
                if (bitArrayIndex < m_length && bitArrayIndex >= 0)
                {
                    m_arrayPtr[bitArrayIndex] |= (MarkedBitFlag << (bitPosition % IntSize));
                }
            }
            else
            {
                int bitArrayIndex = bitPosition / IntSize;
                if (bitArrayIndex < m_length && bitArrayIndex >= 0)
                {
                    m_array[bitArrayIndex] |= (MarkedBitFlag << (bitPosition % IntSize));
                }
            }
        }

        /// <summary>
        /// Is bit at specified position marked?
        /// </summary>
        /// <param name="bitPosition"></param>
        /// <returns></returns>
        [global::System.Security.SecuritySafeCritical]
        internal unsafe bool IsMarked(int bitPosition)
        {
            if (useStackAlloc)
            {
                int bitArrayIndex = bitPosition / IntSize;
                if (bitArrayIndex < m_length && bitArrayIndex >= 0)
                {
                    return ((m_arrayPtr[bitArrayIndex] & (MarkedBitFlag << (bitPosition % IntSize))) != 0);
                }
                return false;
            }
            else
            {
                int bitArrayIndex = bitPosition / IntSize;
                if (bitArrayIndex < m_length && bitArrayIndex >= 0)
                {
                    return ((m_array[bitArrayIndex] & (MarkedBitFlag << (bitPosition % IntSize))) != 0);
                }
                return false;
            }
        }

        /// <summary>
        /// How many ints must be allocated to represent n bits. Returns (n+31)/32, but 
        /// avoids overflow
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        internal static int ToIntArrayLength(int n)
        {
            return n > 0 ? ((n - 1) / IntSize + 1) : 0;
        }

    }
}