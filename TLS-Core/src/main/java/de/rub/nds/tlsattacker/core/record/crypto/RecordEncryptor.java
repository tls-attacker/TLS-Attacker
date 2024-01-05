/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext tlsContext;

    private final RecordNullCipher nullCipher;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext tlsContext) {
        super(recordCipher);
        this.tlsContext = tlsContext;
        nullCipher = RecordCipherFactory.getNullCipher(tlsContext);
    }

    @Override
    public void encrypt(Record record) {
        LOGGER.debug("Encrypting Record:");
        RecordCipher recordCipher;
        if (tlsContext.getChooser().getSelectedProtocolVersion().isDTLS()) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        try {
            record.setSequenceNumber(
                    BigInteger.valueOf(recordCipher.getState().getWriteSequenceNumber()));
            recordCipher.encrypt(record);
        } catch (CryptoException ex) {
            LOGGER.warn("Could not encrypt BlobRecord. Using NullCipher", ex);
            try {
                nullCipher.encrypt(record);
            } catch (CryptoException ex1) {
                LOGGER.error("Could not encrypt with NullCipher", ex1);
            }
        }
        recordCipher.getState().increaseWriteSequenceNumber();
        if (tlsContext.getChooser().getSelectedProtocolVersion().isTLS13()) {
            record.getComputations().setUsedTls13KeySetType(tlsContext.getActiveKeySetTypeWrite());
        }
    }
}
