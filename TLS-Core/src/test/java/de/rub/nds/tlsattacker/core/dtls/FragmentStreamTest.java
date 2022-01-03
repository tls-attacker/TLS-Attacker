/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 *
 * @author ic0ns
 */
public class FragmentStreamTest {

    private FragmentStream stream;

    @Before
    public void setUp() {
        stream = new FragmentStream(10);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of canInsertByteArray method, of class FragmentStream.
     */
    @Test
    public void testCanInsertByteArray() {
        stream.insertByteArray(new byte[] { 0, 1, 2, 3 }, 0);
        assertTrue(stream.canInsertByteArray(new byte[] { 4, 5, 6 }, 4));
        assertTrue(stream.canInsertByteArray(new byte[] { 3, 4, 5 }, 3));
        assertFalse(stream.canInsertByteArray(new byte[] { 4, 4, 5 }, 3));
    }

    /**
     * Test of insertByteArray method, of class FragmentStream.
     */
    @Test
    public void testInsertByteArray() {
        stream.insertByteArray(new byte[] { 1, 2, 3 }, 0);
        stream.insertByteArray(new byte[] { 4, 5, 6 }, 3);
        assertFalse(stream.isComplete(10));
        byte[] completeStream = stream.getCompleteTruncatedStream();
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6 }, completeStream);
        completeStream = stream.getCompleteFilledStream((byte) 0xFF);
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF },
            completeStream);

        stream.insertByteArray(new byte[] { 7, 8, 9, 10 }, 6);
        assertTrue(stream.isComplete(10));
        assertFalse(stream.isComplete(11));
        completeStream = stream.getCompleteTruncatedStream();
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, completeStream);
        completeStream = stream.getCompleteFilledStream((byte) 0xFF);
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, completeStream);
    }

    /**
     * Test of isComplete method, of class FragmentStream.
     */
    @Test
    public void testIsComplete() {
        stream.insertByteArray(new byte[] { 1, 2, 3 }, 0);
        stream.insertByteArray(new byte[] { 7, 8, 9, 10 }, 6);

        assertFalse(stream.isComplete(4));
        assertFalse(stream.isComplete(10));
        assertTrue(stream.isComplete(3));
        assertTrue(stream.isComplete(1));
        assertTrue(stream.isComplete(0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsCompleteNegativeValue() {
        stream.insertByteArray(new byte[] { 1, 2, 3 }, 0);
        stream.isComplete(-4);
    }
}
