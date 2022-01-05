/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol;

import java.math.BigInteger;
import static org.junit.Assert.*;

import de.rub.nds.tlsattacker.core.protocol.Serializer;
import org.junit.Before;
import org.junit.Test;

public class SerializerTest {

    private SerializerImpl serializer;

    @Before
    public void setUp() {
        serializer = new SerializerImpl();
    }

    /**
     * Test of serializeBytes method, of class Serializer.
     */
    @Test
    public void testSerializeBytes() {
        serializer.serializeBytes();
        byte[] result = serializer.getAlreadySerialized();
        assertArrayEquals(result, new byte[] { 0, 1, 2, 3, });
    }

    @Test
    public void testSerializeBigInteger() {
        serializer.appendBigInteger(BigInteger.ZERO, 6);
        assertArrayEquals(new byte[6], serializer.getAlreadySerialized());
    }

    /**
     * Test of appendInt method, of class Serializer.
     */
    @Test
    public void testAppendInt() {
        serializer.appendInt(257, 2);
        byte[] result = serializer.getAlreadySerialized();
        assertArrayEquals(result, new byte[] { 1, 1, });
        serializer = new SerializerImpl();
        serializer.appendInt(257, 1);
        result = serializer.getAlreadySerialized();
        assertArrayEquals(result, new byte[] { 1, });
    }

    /**
     * Test of appendByte method, of class Serializer.
     */
    @Test
    public void testAppendByte() {
        serializer.appendByte((byte) 0x0);
        serializer.appendByte((byte) 0x1);
        byte[] result = serializer.getAlreadySerialized();
        assertArrayEquals(result, new byte[] { 0, 1, });
    }

    /**
     * Test of appendBytes method, of class Serializer.
     */
    @Test
    public void testAppendBytes() {
        serializer.appendBytes(new byte[] { 0, 1, 2, 3, 4, 5, 6 });
        byte[] result = serializer.getAlreadySerialized();
        assertArrayEquals(result, new byte[] { 0, 1, 2, 3, 4, 5, 6, });
    }

    /**
     * Test of serialize method, of class Serializer.
     */
    @Test
    public void testSerialize() {
        byte[] result = serializer.serialize();
        assertArrayEquals(result, new byte[] { 0, 1, 2, 3 });
    }

    public static class SerializerImpl extends Serializer {

        public SerializerImpl() {
            super();
        }

        @Override
        public byte[] serializeBytes() {
            appendBytes(new byte[] { 0, 1, 2, 3 });
            return getAlreadySerialized();
        }
    }

}
