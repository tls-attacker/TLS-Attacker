/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.crypto.RecordDecryptor;
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.Test;

public class EncryptedRecordContentTypeTest {

    @Test
    public void testEncryptedContentType() {
        Config config = new Config();
        State state = new State(config);
        TlsContext context = state.getTlsContext();
        Record record = new Record();

        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        record.setCleanProtocolMessageBytes(new byte[] {0x01, 0x02, 0x03});
        record.prepareComputations();

        KeySet keySet = new KeySet();
        CipherState cipherState =
                new CipherState(
                        ProtocolVersion.TLS13, CipherSuite.TLS_AES_128_GCM_SHA256, keySet, null);
        RecordAEADCipher recordCipher = new RecordAEADCipher(context, cipherState);
        RecordEncryptor encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.HANDSHAKE.getValue(),
                record.getContentMessageType().getValue());

        RecordDecryptor decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.HANDSHAKE.getValue(),
                record.getContentMessageType().getValue());
        assertArrayEquals(
                new byte[] {0x01, 0x02, 0x03}, record.getCleanProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptedAlertContentType() {
        Config config = new Config();
        State state = new State(config);
        TlsContext context = state.getTlsContext();
        Record record = new Record();

        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        byte[] alertBytes =
                new byte[] {
                    AlertLevel.FATAL.getValue(), AlertDescription.INTERNAL_ERROR.getValue()
                };

        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setContentMessageType(ProtocolMessageType.ALERT);
        record.setCleanProtocolMessageBytes(alertBytes);
        record.prepareComputations();

        KeySet keySet = new KeySet();
        CipherState cipherState =
                new CipherState(
                        ProtocolVersion.TLS13, CipherSuite.TLS_AES_128_GCM_SHA256, keySet, null);
        RecordAEADCipher recordCipher = new RecordAEADCipher(context, cipherState);
        RecordEncryptor encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.ALERT.getValue(), record.getContentMessageType().getValue());

        RecordDecryptor decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.ALERT.getValue(), record.getContentMessageType().getValue());
        assertArrayEquals(alertBytes, record.getCleanProtocolMessageBytes().getValue());
    }

    @Test
    public void testEncryptedChangeCipherSpecContentType() {
        Config config = new Config();
        State state = new State(config);
        TlsContext context = state.getTlsContext();
        Record record = new Record();

        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        byte[] ccs = new byte[] {0x01};

        record.setProtocolVersion(ProtocolVersion.TLS13.getValue());
        record.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        record.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        record.setCleanProtocolMessageBytes(ccs);
        record.prepareComputations();

        KeySet keySet = new KeySet();
        CipherState cipherState =
                new CipherState(
                        ProtocolVersion.TLS13, CipherSuite.TLS_AES_128_GCM_SHA256, keySet, null);
        RecordAEADCipher recordCipher = new RecordAEADCipher(context, cipherState);
        RecordEncryptor encryptor = new RecordEncryptor(recordCipher, context);
        encryptor.encrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue(),
                record.getContentMessageType().getValue());

        RecordDecryptor decryptor = new RecordDecryptor(recordCipher, context);
        decryptor.decrypt(record);

        assertEquals(
                ProtocolMessageType.APPLICATION_DATA.getValue(),
                record.getContentType().getValue());
        assertEquals(
                ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue(),
                record.getContentMessageType().getValue());
        assertArrayEquals(ccs, record.getCleanProtocolMessageBytes().getValue());
    }
}
