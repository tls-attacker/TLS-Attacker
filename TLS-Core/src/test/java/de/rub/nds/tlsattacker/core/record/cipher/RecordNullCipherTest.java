/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Pierre Tilhaus
 */
public class RecordNullCipherTest {

    private RecordNullCipher record;
    private byte[] data;

    @Before
    public void setUp() {
        record = new RecordNullCipher();
        data = new byte[] { 1, 2 };
    }

    /**
     * Test of encrypt method, of class RecordNullCipher.
     */
    @Test
    public void testEncrypt() {
        assertArrayEquals(record.encrypt(data), data);
    }

    /**
     * Test of decrypt method, of class RecordNullCipher.
     */
    @Test
    public void testDecrypt() {
        assertArrayEquals(record.decrypt(data), data);
    }

    /**
     * Test of calculateMac method, of class RecordNullCipher.
     */
    @Test (expected = UnsupportedOperationException.class)
    public void testCalculateMac() {
        record.calculateMac(data);
    }

    /**
     * Test of getMacLength method, of class RecordNullCipher.
     */
    @Test
    public void testGetMacLength() {
        assertEquals(record.getMacLength(), 0);
    }

    /**
     * Test of calculatePadding method, of class RecordNullCipher.
     */
    @Test
    public void testCalculatePadding() {
        assertArrayEquals(record.calculatePadding(10), new byte[0]);
    }

    /**
     * Test of getPaddingLength method, of class RecordNullCipher.
     */
    @Test
    public void testGetPaddingLength() {
        assertEquals(record.getPaddingLength(0), 0);
    }

}
