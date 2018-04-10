/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.DecryptionRequest;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.EncryptionRequest;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RecordNullCipherTest {

    private RecordNullCipher record;
    private byte[] data;

    @Before
    public void setUp() {
        record = new RecordNullCipher(new TlsContext());
        data = new byte[] { 1, 2 };
    }

    /**
     * Test of encrypt method, of class RecordNullCipher.
     */
    @Test
    public void testEncrypt() {
        assertArrayEquals(record.encrypt(new EncryptionRequest(data, null, null)).getCompleteEncryptedCipherText(),
                data);
    }

    /**
     * Test of decrypt method, of class RecordNullCipher.
     */
    @Test
    public void testDecrypt() {
        assertArrayEquals(record.decrypt(new DecryptionRequest(null, data)).getDecryptedCipherText(), data);
    }

    /**
     * Test of calculateMac method, of class RecordNullCipher.
     */
    @Test
    public void testCalculateMac() {
        assertArrayEquals(record.calculateMac(data, ConnectionEndType.CLIENT), new byte[0]);
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
        assertEquals(record.calculatePaddingLength(0), 0);
    }

}
