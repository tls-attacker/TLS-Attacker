/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.record.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.BlobRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordDecryptor extends Decryptor {

    private static final Logger LOGGER = LogManager.getLogger();

    private final TlsContext context;

    public RecordDecryptor(RecordCipher recordCipher, TlsContext context) {
        super(recordCipher);
        this.context = context;
    }

    @Override
    public void decrypt(BlobRecord record) throws CryptoException {
        LOGGER.debug("Decrypting BlobRecord");
        recordCipher.decrypt(record);
    }

    @Override
    public void decrypt(Record record) throws CryptoException {
        LOGGER.debug("Decrypting Record");
        record.prepareComputations();
        recordCipher.decrypt(record);
        context.increaseReadSequenceNumber();
        if (context.getChooser().getConnectionEndType() == ConnectionEndType.SERVER
                && context.getActiveClientKeySetType() == Tls13KeySetType.EARLY_TRAFFIC_SECRETS) {
            checkForEndOfEarlyData(record.getComputations().getUnpaddedRecordBytes().getValue());
        }
    }

    private void checkForEndOfEarlyData(byte[] unpaddedBytes) throws CryptoException {
        byte[] endOfEarlyData = new byte[] { 5, 0, 0, 0 };
        if (Arrays.equals(unpaddedBytes, endOfEarlyData)) {
            adjustClientCipherAfterEarly();
        }
    }

    public void adjustClientCipherAfterEarly() throws CryptoException {
        try {
            context.setActiveClientKeySetType(Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS);
            LOGGER.debug("Setting cipher for client to use handshake secrets");
            KeySet clientKeySet = KeySetGenerator.generateKeySet(context, context.getChooser()
                    .getSelectedProtocolVersion(), context.getActiveClientKeySetType());
            RecordCipher recordCipherClient = RecordCipherFactory.getRecordCipher(context, clientKeySet, context
                    .getChooser().getSelectedCipherSuite());
            context.getRecordLayer().setRecordCipher(recordCipherClient);
            context.getRecordLayer().updateDecryptionCipher();
            context.setReadSequenceNumber(0);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error("Generating KeySet failed - Unknown algorithm");
            throw new WorkflowExecutionException(ex.toString());
        }
    }
}
