/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    private RecordNullCipher nullCipher;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
        nullCipher = new RecordNullCipher(context);
    }

    @Override
    public void decrypt(BlobRecord record) {
        LOGGER.warn("We are not decrypting BlobRecords. Using NullCipher");
        try {
            nullCipher.decrypt(record);
        } catch (CryptoException ex1) {
            LOGGER.warn("Could not decrypt BlobRecord with NullCipher", ex1);
        }
    }

    @Override
    public void decrypt(Record record) {
        LOGGER.debug("Decrypting Record");
        RecordCipher recordCipher;
        if (context.getChooser().getSelectedProtocolVersion().isDTLS() && record.getEpoch() != null
            && record.getEpoch().getValue() != null) {
            recordCipher = getRecordCipher(record.getEpoch().getValue());
        } else {
            recordCipher = getRecordMostRecentCipher();
        }
        record.prepareComputations();
        record.setSequenceNumber(BigInteger.valueOf(context.getReadSequenceNumber()));
        try {
            recordCipher.decrypt(record);
        } catch (CryptoException | ParserException ex) {
            LOGGER.warn("Could not decrypt Record. Using NullCipher instead", ex);
            try {
                nullCipher.decrypt(record);
            } catch (CryptoException ex1) {
                LOGGER.warn("Could not decrypt Record with null cipher", ex1);
            }
        }
        context.increaseReadSequenceNumber();
    }
}
