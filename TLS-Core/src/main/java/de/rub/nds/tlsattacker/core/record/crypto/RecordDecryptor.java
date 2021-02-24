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
        if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
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
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
            && context.getActiveClientKeySetType() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            checkForEndOfEarlyData(record.getCleanProtocolMessageBytes().getValue());
        }
    }

    private void checkForEndOfEarlyData(byte[] unpaddedBytes) {
        byte[] endOfEarlyData = new byte[] { 5, 0, 0, 0 };
        if (Arrays.equals(unpaddedBytes, endOfEarlyData)) {
            adjustClientCipherAfterEarly();
        }
    }

    public void adjustClientCipherAfterEarly() {
        try {
            context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use handshake secrets");
            KeySet clientKeySet = KeySetGenerator.generateKeySet(context,
                context.getChooser().getSelectedProtocolVersion(), context.getActiveClientKeySetType());
            RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(context, clientKeySet,
                context.getChooser().getSelectedCipherSuite());
            context.getRecordLayer().setRecordCipher(recordCipherClient);
            context.getRecordLayer().updateDecryptionCipher();
            context.setReadSequenceNumber(0);
        } catch (CryptoException | NoSuchAlgorithmException ex) {
            LOGGER.error("Generating KeySet failed", ex);
            throw new WorkflowExecutionException(ex.toString());
        }
    }
}
