/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public class VariableLengthIntegerEncoding {

    public static byte[] encodeVariableLengthInteger(long value) {
        if (value > EncodingLength.SIXTY_BITS.maxValue) {
            return null;
        }
        byte[] result;
        if (value <= EncodingLength.SIX_BITS.maxValue) {
            result = ArrayConverter.longToBytes(value, 1);
        } else if (value <= EncodingLength.FOURTEEN_BITS.maxValue) {
            result = ArrayConverter.longToBytes(value, 2);
            result[0] = (byte) (result[0] | 0x40);
        } else if (value <= EncodingLength.THIRTY_BITS.maxValue) {
            result = ArrayConverter.longToBytes(value, 4);
            result[0] = (byte) (result[0] | 0x80);
        } else {
            result = ArrayConverter.longToBytes(value, 8);
            result[0] = (byte) (result[0] | 0xc0);
        }
        return result;
    }

    /**
     * Decode variable length integer from fixed byte array. Used in cases where the length of the
     * field is separately encoded and it can be parsed without relying on the prefix (Transport
     * Parameters with separate length field)
     *
     * @param bytes which hold the encoded integer
     * @return decoded integer as java long
     */
    public static long decodeVariableLengthInteger(byte[] bytes) {
        long v = bytes[0];
        byte prefix = (byte) ((v & 0xff) >> 6);
        byte length = (byte) ((1 & 0xff) << prefix);
        v = (byte) v & 0x3f;
        for (int i = 1; i < length; i++) {
            v = (v << 8) + (bytes[i] & 0xff);
        }
        return v;
    }

    public enum EncodingLength {
        SIX_BITS(63),
        FOURTEEN_BITS(16383),
        THIRTY_BITS(1073741823),
        SIXTY_BITS(4611686018427387903L);

        private final long maxValue;

        EncodingLength(long maxValue) {
            this.maxValue = maxValue;
        }

        public long getMaxValue() {
            return maxValue;
        }
    }
}
