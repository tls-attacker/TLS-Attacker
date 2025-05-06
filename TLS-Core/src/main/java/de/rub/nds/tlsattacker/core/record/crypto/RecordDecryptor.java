/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext tlsContext) {
        super(recordCipher);
        this.tlsContext = tlsContext;
    }

    @Override
    public void decrypt(Record record) throws ParserException {
        LOGGER.debug("Decrypting Record");
        RecordCipher recordCipher;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()
                && record.getEpoch() != null
                && record.getEpoch().getValue() != null) {
            // After handshake DTLS 1.3 Epochs must be guessed based on the last 2 bits
            if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS13()
                    && tlsContext.getReadEpoch() > 3
                    && record.getUnifiedHeader() != null) {
                recordCipher = getRecordCipherForEpochBits(record.getEpoch().getValue(), record);
                if (recordCipher == null) {
                    LOGGER.warn(
                            "Got no RecordCipher for epoch bits: {}. Using most recent cipher instead.",
                            record.getEpoch().getValue());
                    recordCipher = getRecordMostRecentCipher();
                }
            } else {
                recordCipher = getRecordCipher(record.getEpoch().getValue());
            }
            // Decrypt encrypted record sequence numbers in DTLS 1.3
            if (record.getEncryptedSequenceNumber() != null) {
                try {
                    recordCipher.decryptDtls13SequenceNumber(record);
                } catch (CryptoException ex) {
                    LOGGER.error("Could not decrypt DTLS 1.3 Record Sequence Number: {}", ex);
                }
            }
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        record.prepareComputations();
        ProtocolVersion version =
                ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());
        if (version == null || !version.isDTLS()) {
            record.setSequenceNumber(
                    BigInteger.valueOf(recordCipher.getState().getReadSequenceNumber()));
        }

        try {
            if (!tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()
                    || record.getContentMessageType() != ProtocolMessageType.CHANGE_CIPHER_SPEC) {
                try {
                    recordCipher.decrypt(record);
                } catch (ParserException | CryptoException ex) {
                    if (recordCipherList.indexOf(recordCipher) > 0) {
                        LOGGER.warn(
                                "Failed to decrypt record, will try to process with previous cipher");
                        recordCipherList
                                .get(recordCipherList.indexOf(recordCipher) - 1)
                                .decrypt(record);
                    }
                }
                recordCipher.getState().increaseReadSequenceNumber();
            } else {
                LOGGER.debug("Skipping decryption for legacy CCS");
                new RecordNullCipher(tlsContext, recordCipher.getState()).decrypt(record);
            }
        } catch (CryptoException ex) {
            throw new ParserException(ex);
        }
    }
}
