/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.cipher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RecordNullCipherTest {

    private RecordNullCipher recordCipher;
    private byte[] data;
    private Record record;

    @BeforeEach
    public void setUp() {
        TlsContext ctx = new TlsContext();
        recordCipher = RecordCipherFactory.getNullCipher(ctx);
        data = new byte[] {1, 2};
        record = new Record();
    }

    /** Test of encrypt method, of class RecordNullCipher. */
    @Test
    public void testEncrypt() throws CryptoException {
        record.setCleanProtocolMessageBytes(data);
        recordCipher.encrypt(record);
        assertArrayEquals(record.getProtocolMessageBytes().getValue(), data);
    }

    /** Test of decrypt method, of class RecordNullCipher. */
    @Test
    public void testDecrypt() throws CryptoException {
        record.setProtocolMessageBytes(data);
        recordCipher.decrypt(record);
        assertArrayEquals(data, record.getCleanProtocolMessageBytes().getValue());
    }
}
