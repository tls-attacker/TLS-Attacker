/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Florian Pfützenreuter <Florian.Pfuetzenreuter@rub.de>
 */
public class ArrayConverterTest {

    /**
     * Test of longToUint64Bytes method, of class ArrayConverter.
     */
    @Test
    public void testLongToUint64Bytes() {
    }

    /**
     * Test of longToUint32Bytes method, of class ArrayConverter.
     */
    @Test
    public void testLongToUint32Bytes() {
    }

    /**
     * Test of intToBytes method, of class ArrayConverter.
     */
    @Test
    public void testIntToBytes() {
    }

    /**
     * Test of bytesToInt method, of class ArrayConverter.
     */
    @Test
    public void testBytesToInt() {
        byte[] toParse = { 0x16, 0x55 };
        int result = ArrayConverter.bytesToInt(toParse);
        assertEquals("The conversion result of {0x16, 0x55} should be 5717", 5717, result);
    }

    /**
     * Test of bytesToLong method, of class ArrayConverter.
     */
    @Test
    public void testBytesToLong() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr() {
        byte[] toTest = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44 };
        assertEquals("00 11 22 33 44", ArrayConverter.bytesToHexString(toTest));
        toTest = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        assertEquals("00 01 02 03 04 05 06 07 08", ArrayConverter.bytesToHexString(toTest));
        toTest = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10 };
        assertEquals("00 01 02 03 04 05 06 07 08 09 10", ArrayConverter.bytesToHexString(toTest));
        toTest = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, };
        assertEquals("\n00 01 02 03 04 05 06 07  00 01 02 03 04 05 06 07", ArrayConverter.bytesToHexString(toTest));
        toTest = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, };
        assertEquals(
                "\n00 01 02 03 04 05 06 07  00 01 02 03 04 05 06 07\n00 01 02 03 04 05 06 07  00 01 02 03 04 05 06 07",
                ArrayConverter.bytesToHexString(toTest));
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr_int() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr_boolean() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_3args() {
    }

    /**
     * Test of concatenate method, of class ArrayConverter.
     */
    @Test
    public void testConcatenate_GenericType() {
    }

    /**
     * Test of concatenate method, of class ArrayConverter.
     */
    @Test
    public void testConcatenate_byteArrArr() {
    }

    /**
     * Test of makeArrayNonZero method, of class ArrayConverter.
     */
    @Test
    public void testMakeArrayNonZero() {
    }

    /**
     * Test of bigIntegerToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testBigIntegerToByteArray_3args() {
    }

    /**
     * Test of bigIntegerToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testBigIntegerToByteArray_BigInteger() {
    }

    /**
     * Test of convertListToArray method, of class ArrayConverter.
     */
    @Test
    public void testConvertListToArray() {
    }

    /**
     * Test of hexStringToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testHexStringToByteArray() {
        String hex = "01";
        assertArrayEquals("Testing simple one byte hex value", new byte[] { 0x01 },
                ArrayConverter.hexStringToByteArray(hex));
        hex = "FF";
        assertArrayEquals("Testing one byte hex value > 0x7f", new byte[] { (byte) 0xff },
                ArrayConverter.hexStringToByteArray(hex));
        hex = "FFFFFF";
        assertArrayEquals("Testing one byte hex value > 0x7f", new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff },
                ArrayConverter.hexStringToByteArray(hex));
    }

    @Test
    public void testBigIntegerToNullPaddedByteArray() {
        BigInteger test = new BigInteger("1D42C86F7923DFEC", 16);

        assertArrayEquals("Check zero output size", new byte[0],
                ArrayConverter.bigIntegerToNullPaddedByteArray(test, 0));
        assertArrayEquals("Check check output size smaller than input", new byte[] { (byte) 0xEC },
                ArrayConverter.bigIntegerToNullPaddedByteArray(test, 1));
        assertArrayEquals("Check output size bigger than input size",
                ArrayConverter.hexStringToByteArray("0000000000000000000000001D42C86F7923DFEC"),
                ArrayConverter.bigIntegerToNullPaddedByteArray(test, 20));
    }

    @Test
    public void testLongToUint48Bytes() {
        long testValue = 0x0000123456789ABCL;
        byte[] expectedResult = ArrayConverter.hexStringToByteArray("123456789ABC");

        assertArrayEquals("Assert correct output", expectedResult, ArrayConverter.longToUint48Bytes(testValue));

        testValue = 0x0000000000000001L;
        expectedResult = ArrayConverter.hexStringToByteArray("000000000001");

        assertArrayEquals("Assert correct output", expectedResult, ArrayConverter.longToUint48Bytes(testValue));
    }
}
