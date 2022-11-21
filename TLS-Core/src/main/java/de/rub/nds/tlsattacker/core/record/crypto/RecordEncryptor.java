/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordEncryptor extends Encryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private final RecordNullCipher nullCipher;

    public RecordEncryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
        nullCipher = RecordCipherFactory.getNullCipher(context);
    }

    @Override
    public void encrypt(BlobRecord record) {
        LOGGER.debug("Encrypting BlobRecord");
        RecordCipher recordCipher = getRecordMostRecentCipher();
        try {
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
    }

    @Override
    public void encrypt(Record record) {
        LOGGER.debug("Encrypting Record:");
        RecordCipher recordCipher;
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        try {
            record.setSequenceNumber(BigInteger.valueOf(recordCipher.getState().getWriteSequenceNumber()));
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
        if (context.getChooser().getSelectedProtocolVersion().isTLS13()) {
            record.getComputations().setUsedTls13KeySetType(context.getActiveKeySetTypeWrite());
        }
    }
}
