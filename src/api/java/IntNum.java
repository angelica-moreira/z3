/**
Copyright (c) 2012-2014 Microsoft Corporation
   
Module Name:

    IntNum.java

Abstract:

Author:

    @author Christoph Wintersteiger (cwinter) 2012-03-15

Notes:
    
**/ 

package com.microsoft.z3;

import java.math.BigInteger;

/**
 * Integer Numerals
 **/
public class IntNum extends IntExpr
{

    IntNum(Context ctx, long obj)
    {
        super(ctx, obj);
    }

    /**
     * Retrieve the int value.
     **/
    public int getInt()
    {
        Native.IntPtr res = new Native.IntPtr();
        if (!Native.getNumeralInt(getContext().nCtx(), getNativeObject(), res))
            throw new Z3Exception("Numeral is not an int");
        return res.value;
    }

    /**
     * Retrieve the 64-bit int value.
     **/
    public long getInt64()
    {
        Native.LongPtr res = new Native.LongPtr();
        if (!Native.getNumeralInt64(getContext().nCtx(), getNativeObject(), res))
            throw new Z3Exception("Numeral is not an int64");
        return res.value;
    }

    /**
     * Retrieve the unsigned 32-bit value.
     * <p>
     * The value is returned as a Java {@code int} containing the raw 32-bit
     * two's-complement bit pattern of the underlying unsigned integer. For
     * values greater than {@code 0x7FFFFFFF} ({@code 2^31 - 1}), the returned
     * {@code int} will be negative when interpreted as a signed value.
     * <p>
     * To interpret the result as an unsigned 32-bit value, use the standard
     * Java unsigned helpers, for example:
     * <pre>
     *   int v = intNum.getUint();
     *   long unsignedNumeric = Integer.toUnsignedLong(v);
     *   String unsignedString = Integer.toUnsignedString(v);
     * </pre>
     *
     * @return the underlying 32-bit unsigned value encoded in a Java {@code int}
     */
    public int getUint()
    {
        Native.IntPtr res = new Native.IntPtr();
        if (!Native.getNumeralUint(getContext().nCtx(), getNativeObject(), res))
            throw new Z3Exception("Numeral is not a uint");
        return res.value;
    }

    /**
     * Retrieve the unsigned 64-bit value.
     * <p>
     * The value is returned as a Java {@code long} containing the raw 64-bit
     * two's-complement bit pattern of the underlying unsigned integer. For
     * values greater than {@code 0x7FFFFFFFFFFFFFFFL} ({@code 2^63 - 1}),
     * the returned {@code long} will be negative when interpreted as a signed
     * value.
     * <p>
     * To obtain an unsigned representation, you can use:
     * <pre>
     *   long v = intNum.getUint64();
     *   String unsignedString = Long.toUnsignedString(v);
     * </pre>
     * or use {@link #getBigInteger()} to retrieve the value as a
     * {@link java.math.BigInteger} if you need an explicit arbitrary-precision
     * numeric type.
     *
     * @return the underlying 64-bit unsigned value encoded in a Java {@code long}
     */
    public long getUint64()
    {
        Native.LongPtr res = new Native.LongPtr();
        if (!Native.getNumeralUint64(getContext().nCtx(), getNativeObject(), res))
            throw new Z3Exception("Numeral is not a uint64");
        return res.value;
    }

    /**
     * Retrieve the BigInteger value.
     **/
    public BigInteger getBigInteger()
    {
        return new BigInteger(this.toString());
    }

    /**
     * Returns a string representation of the numeral.
     **/
    public String toString() {
        return Native.getNumeralString(getContext().nCtx(), getNativeObject());
    }
}
