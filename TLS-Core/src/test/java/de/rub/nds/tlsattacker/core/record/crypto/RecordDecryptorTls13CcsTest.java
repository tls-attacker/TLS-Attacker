/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordAEADCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test class to ensure that a legacy CCS sent between a TLS 1.3 ServerHello and EncryptedExtensions
 * does not get decrypted and parsed correctly.
 */
class RecordDecryptorTls13CcsTest {

    private RecordCipher recordCipher;
    private TlsContext context;
    private Record ccsRecord;
    private RecordDecryptor decryptor;

    @BeforeEach
    void setUp() {
        context = new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        ccsRecord = new Record();
    }

    /**
     * Test that a CCS record in TLS 1.3 is not decrypted between ServerHello and
     * EncryptedExtensions. According to RFC 8446, CCS messages in TLS 1.3 are treated as legacy
     * compatibility messages and should not be decrypted.
     */
    @Test
    void testTls13CcsNotDecrypted() {
        // Set up TLS 1.3 context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

        // Set up dummy keys for the handshake phase
        KeySet keySet = new KeySet();
        keySet.setServerWriteKey(new byte[16]); // 128-bit key for AES-128
        keySet.setServerWriteIv(new byte[12]); // 96-bit IV for GCM
        keySet.setClientWriteKey(new byte[16]);
        keySet.setClientWriteIv(new byte[12]);

        // Create a CCS record
        ccsRecord.setContentType(ProtocolMessageType.CHANGE_CIPHER_SPEC.getValue());
        ccsRecord.setContentMessageType(ProtocolMessageType.CHANGE_CIPHER_SPEC);
        ccsRecord.setProtocolVersion(ProtocolVersion.TLS12.getValue()); // Legacy version
        ccsRecord.setLength(1);
        ccsRecord.setProtocolMessageBytes(new byte[] {0x01}); // CCS payload

        // Create cipher state with handshake traffic keys
        CipherState cipherState =
                new CipherState(
                        context.getChooser().getSelectedProtocolVersion(),
                        context.getChooser().getSelectedCipherSuite(),
                        keySet,
                        false);

        // Create the record cipher
        recordCipher = new RecordAEADCipher(context, cipherState);

        // Create decryptor
        decryptor = new RecordDecryptor(recordCipher, context);

        // Attempt to decrypt the CCS record
        decryptor.decrypt(ccsRecord);

        // Verify that the record was NOT decrypted
        // In TLS 1.3, CCS should be passed through without decryption
        assertNotNull(ccsRecord.getCleanProtocolMessageBytes());
        assertArrayEquals(new byte[] {0x01}, ccsRecord.getCleanProtocolMessageBytes().getValue());

        // Verify that no cryptographic operations were performed
        assertNull(ccsRecord.getComputations().getAuthenticatedMetaData());
        assertNull(ccsRecord.getComputations().getAuthenticatedNonMetaData());
        assertNull(ccsRecord.getComputations().getGcmNonce());
        assertNull(ccsRecord.getComputations().getCipherKey());
    }

    /**
     * Test that a regular handshake message (not CCS) in TLS 1.3 does get decrypted properly for
     * comparison.
     */
    @Test
    void testTls13HandshakeMessageDecrypted() {
        // Set up TLS 1.3 context
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setActiveServerKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);

        // Set up dummy keys for the handshake phase
        KeySet keySet = new KeySet();
        keySet.setServerWriteKey(new byte[16]); // 128-bit key for AES-128
        keySet.setServerWriteIv(new byte[12]); // 96-bit IV for GCM
        keySet.setClientWriteKey(new byte[16]);
        keySet.setClientWriteIv(new byte[12]);

        // Create a regular handshake record (not CCS)
        Record handshakeRecord = new Record();
        handshakeRecord.setContentType(ProtocolMessageType.APPLICATION_DATA.getValue());
        handshakeRecord.setContentMessageType(ProtocolMessageType.HANDSHAKE);
        handshakeRecord.setProtocolVersion(ProtocolVersion.TLS12.getValue());
        handshakeRecord.setLength(32);
        handshakeRecord.setProtocolMessageBytes(new byte[32]); // Dummy encrypted data

        // Create cipher state
        CipherState cipherState =
                new CipherState(
                        context.getChooser().getSelectedProtocolVersion(),
                        context.getChooser().getSelectedCipherSuite(),
                        keySet,
                        false);

        // Create the record cipher
        recordCipher = new RecordAEADCipher(context, cipherState);

        // Create decryptor
        decryptor = new RecordDecryptor(recordCipher, context);

        // This should attempt decryption (even if it fails with our dummy data)
        try {
            decryptor.decrypt(handshakeRecord);
        } catch (Exception e) {
            // Expected to fail with dummy data
        }

        // Verify that cryptographic computations were attempted
        assertNotNull(handshakeRecord.getComputations());
        // The decryptor should have attempted to set up crypto parameters
        // For TLS 1.3, at least some crypto computations should be present
        assertNotNull(handshakeRecord.getComputations().getGcmNonce());
        assertNotNull(handshakeRecord.getComputations().getAuthenticatedMetaData());
        assertNotNull(handshakeRecord.getComputations().getCipherKey());
    }
}
