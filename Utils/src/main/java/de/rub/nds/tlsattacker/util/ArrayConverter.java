/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ArrayConverter {

    /**
     * Takes a long value and converts it to 8 bytes (needed for example to
     * convert SQN numbers in TLS records)
     *
     * @param l
     * @return
     */
    public static byte[] longToUint64Bytes(long l) {
        byte[] result = new byte[8];
        result[0] = (byte) (l >>> 56);
        result[1] = (byte) (l >>> 48);
        result[2] = (byte) (l >>> 40);
        result[3] = (byte) (l >>> 32);
        result[4] = (byte) (l >>> 24);
        result[5] = (byte) (l >>> 16);
        result[6] = (byte) (l >>> 8);
        result[7] = (byte) (l);
        return result;
    }

    /**
     * Takes a long value and converts it to 4 bytes
     *
     * @param l
     * @return
     */
    public static byte[] longToUint32Bytes(long l) {
        byte[] result = new byte[4];
        result[0] = (byte) (l >>> 24);
        result[1] = (byte) (l >>> 16);
        result[2] = (byte) (l >>> 8);
        result[3] = (byte) (l);
        return result;
    }

    /**
     * Takes an integer value and stores its last bytes into a byte array
     *
     * @param value
     *            integer value
     * @param size
     *            byte size of the new integer byte array
     * @return
     */
    public static byte[] intToBytes(int value, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("The array must be at least of size 1");
        }
        byte[] result = new byte[size];
        int shift = 0;
        for (int i = size - 1; i >= 0; i--) {
            result[i] = (byte) (value >>> shift);
            shift += 8;
        }

        return result;
    }

    /**
     * Takes a long value and stores its last bytes into a byte array
     *
     * @param value
     *            long value
     * @param size
     *            byte size of the new integer byte array
     * @return
     */
    public static byte[] longToBytes(long value, int size) {
        if (size < 1) {
            throw new IllegalArgumentException("The array must be at least of size 1");
        }
        byte[] result = new byte[size];
        int shift = 0;
        for (int i = size - 1; i >= 0; i--) {
            result[i] = (byte) (value >>> shift);
            shift += 8;
        }

        return result;
    }

    /**
     * Converts multiple bytes into one int value
     *
     * @param value
     * @return
     */
    public static int bytesToInt(byte[] value) {
        int result = 0;
        int shift = 0;
        for (int i = value.length - 1; i >= 0; i--) {
            result += (value[i] & 0xFF) << shift;
            shift += 8;
        }
        return result;
    }

    /**
     * Converts multiple bytes into one long value
     *
     * @param value
     * @return
     */
    public static long bytesToLong(byte[] value) {
        int result = 0;
        int shift = 0;
        for (int i = value.length - 1; i >= 0; i--) {
            result += (value[i] & 0xFF) << shift;
            shift += 8;
        }
        return result;
    }

    public static String bytesToHexString(byte[] array) {
        if (array == null) {
            array = new byte[0];
        }
        return bytesToHexString(array, array.length);
    }

    public static String bytesToHexString(byte[] array, int byteSize) {
        boolean usePrettyPrinting = (byteSize > 15);
        return bytesToHexString(array, byteSize, usePrettyPrinting);
    }

    public static String bytesToHexString(byte[] array, boolean usePrettyPrinting) {
        if (array == null) {
            array = new byte[0];
        }
        return bytesToHexString(array, array.length, usePrettyPrinting);
    }

    public static String bytesToHexString(byte[] array, int byteSize, boolean usePrettyPrinting) {
        if (array == null) {
            array = new byte[0];
        }
        return bytesToHexString(array, array.length, usePrettyPrinting, true);
    }

    public static String bytesToHexString(byte[] array, int byteSize, boolean usePrettyPrinting, boolean initialNewLine) {
        StringBuilder result = new StringBuilder();
        int bs = (byteSize < array.length) ? byteSize : array.length;
        if (initialNewLine && usePrettyPrinting) {
            result.append("\n");
        }
        for (int i = 0; i < bs; i++) {
            if (usePrettyPrinting && i != 0) {
                if (i % 16 == 0) {
                    result.append("\n");
                } else if (i % 8 == 0) {
                    result.append(" ");
                }
            }
            if (i % 16 != 0) {
                result.append(" ");
            }
            byte b = array[i];
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    @SafeVarargs
    public static <T> T[] concatenate(final T[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("The minimal number of parameters for this function is one");
        }
        int length = 0;
        for (final T[] a : arrays) {
            length += a.length;
        }
        @SuppressWarnings("unchecked")
        T[] result = (T[]) Array.newInstance(arrays[0].getClass().getComponentType(), length);
        int currentOffset = 0;
        for (final T[] a : arrays) {
            System.arraycopy(a, 0, result, currentOffset, a.length);
            currentOffset += a.length;
        }
        return result;
    }

    public static byte[] concatenate(final byte[]... arrays) {
        if (arrays == null || arrays.length == 0) {
            throw new IllegalArgumentException("The minimal number of parameters for this function is one");
        }
        int length = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                length += a.length;
            }
        }
        byte[] result = new byte[length];
        int currentOffset = 0;
        for (final byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, result, currentOffset, a.length);
                currentOffset += a.length;
            }
        }
        return result;
    }

    public static byte[] concatenate(final byte[] array1, final byte[] array2, int numberOfArray2Bytes) {
        int length = array1.length + numberOfArray2Bytes;
        byte[] result = new byte[length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, numberOfArray2Bytes);
        return result;
    }

    public static void makeArrayNonZero(final byte[] array) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] == 0) {
                array[i] = 1;
            }
        }
    }

    /**
     * Takes a BigInteger value and returns its byte array representation filled
     * with 0x00 bytes to achieve the block size length.
     *
     * @param value
     * @param blockSize
     * @param removeSignByte
     *            in a case the removeSignByte is set, the sign byte is removed
     *            (in case the byte array contains one)
     * @return
     */
    public static byte[] bigIntegerToByteArray(BigInteger value, int blockSize, boolean removeSignByte) {
        byte[] array = value.toByteArray();
        int remainder = array.length % blockSize;
        byte[] result = array;
        byte[] tmp;

        if (removeSignByte && result[0] == 0x0) {
            tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
            remainder = tmp.length % blockSize;
        }

        if (remainder > 0) {
            // add zeros to fit size
            tmp = new byte[result.length + blockSize - remainder];
            System.arraycopy(result, 0, tmp, blockSize - remainder, result.length);
            result = tmp;
        }

        return result;
    }

    /**
     * Takes a BigInteger value and returns its byte array representation, if
     * necessary the sign byte is removed.
     *
     * @param value
     * @return
     */
    public static byte[] bigIntegerToByteArray(BigInteger value) {
        byte[] result = value.toByteArray();

        if (result[0] == 0x0) {
            byte[] tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
        }
        return result;
    }

    /**
     * Converts a list of BigIntegers to an array
     *
     * @param list
     * @return
     */
    public static BigInteger[] convertListToArray(List<BigInteger> list) {
        BigInteger[] result = new BigInteger[list.size()];
        for (int i = 0; i < list.size(); i++) {
            result[i] = list.get(i);
        }
        return result;
    }

    /**
     * Converts a string with an even number of hexadecimal characters to a byte
     * array.
     *
     * @param input
     * @return
     */
    public static byte[] hexStringToByteArray(String input) {
        if ((input == null) || (input.length() % 2 != 0)) {
            throw new IllegalArgumentException("The input must not be null and "
                    + "shall have an even number of hexadecimal characters. Found: " + input);
        }
        byte[] output = new byte[input.length() / 2];
        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) ((Character.digit(input.charAt(i * 2), 16) << 4) + Character.digit(
                    input.charAt(i * 2 + 1), 16));
        }
        return output;
    }

    /**
     * Converts a BigInteger into a byte array of given size. If the BigInteger
     * doesn't fit into the byte array, bits of the BigInteger will simply be
     * truncated, starting with the most significant bit. If the array is larger
     * than the BigInteger, prepending bytes in the array will be 0x00.
     *
     * @param input
     * @param outputSizeInBytes
     * @return
     */
    public static byte[] bigIntegerToNullPaddedByteArray(BigInteger input, int outputSizeInBytes) {
        if (input == null) {
            throw new IllegalArgumentException("'input' must not be null.");
        }
        byte[] output = new byte[outputSizeInBytes];

        int numByteBlocks = input.bitLength() / 8;
        int remainingBits;

        if (numByteBlocks < output.length) {
            remainingBits = input.bitLength() % 8;
        } else {
            remainingBits = 0;
            numByteBlocks = output.length;
        }

        int i;
        for (i = 0; i < numByteBlocks; i++) {
            output[output.length - 1 - i] = input.shiftRight(i * 8).byteValue();
        }
        if (remainingBits > 0) {
            output[output.length - 1 - i] = input.shiftRight(i * 8).byteValue();
        }
        return output;
    }

    public static byte[] longToUint48Bytes(long input) {
        byte[] output = new byte[6];

        output[0] = (byte) (input >>> 40);
        output[1] = (byte) (input >>> 32);
        output[2] = (byte) (input >>> 24);
        output[3] = (byte) (input >>> 16);
        output[4] = (byte) (input >>> 8);
        output[5] = (byte) input;

        return output;
    }
}
