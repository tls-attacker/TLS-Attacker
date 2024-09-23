/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class VariableLengthIntegerEncodingTest {

    @Test
    public void testEncodeVariableLengthInteger() {
        // 1 byte length min
        assertArrayEquals(
                new byte[] {0b00000000},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(0));
        // 1 byte length max
        assertArrayEquals(
                new byte[] {0b00111111},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(63));
        // 2 byte length min
        assertArrayEquals(
                new byte[] {0b01000000, 0b01000000},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(64));
        // 2 byte length max
        assertArrayEquals(
                new byte[] {0b01111111, (byte) 0xff},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(16383));
        // 4 byte length min
        assertArrayEquals(
                new byte[] {(byte) 0b10000000, 0x00, 0b01000000, 0x00},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(16384));
        // 4 byte length max
        assertArrayEquals(
                new byte[] {(byte) 0b10111111, (byte) 0xff, (byte) 0xff, (byte) 0xff},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(1073741823));
        // 8 byte length min
        assertArrayEquals(
                new byte[] {(byte) 0b11000000, 0x00, 0x00, 0x00, 0b01000000, 0x00, 0x00, 0x00},
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(1073741824));
        // 8 byte length max
        assertArrayEquals(
                new byte[] {
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff
                },
                VariableLengthIntegerEncoding.encodeVariableLengthInteger(4611686018427387903L));
    }

    @Test
    public void testDecodeVariableLengthInteger() {
        // 1 byte length min
        byte[] bytesToDecode = new byte[] {0b00000000};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 1 byte length max
        bytesToDecode = new byte[] {0b00111111};
        assertEquals(63, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 2 byte length min
        bytesToDecode = new byte[] {(byte) 0b01000000, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 2 byte length max
        bytesToDecode = new byte[] {(byte) 0b01111111, (byte) 0xff};
        assertEquals(
                16383, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 4 byte length min
        bytesToDecode = new byte[] {(byte) 0b10000000, 0x00, 0x00, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 4 byte length max
        bytesToDecode = new byte[] {(byte) 0b10111111, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertEquals(
                1073741823,
                VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 8 byte length min
        bytesToDecode = new byte[] {(byte) 0b11000000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        assertEquals(0, VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
        // 8 byte length max
        bytesToDecode =
                new byte[] {
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff,
                    (byte) 0xff
                };
        assertEquals(
                4611686018427387903L,
                VariableLengthIntegerEncoding.decodeVariableLengthInteger(bytesToDecode));
    }
}
