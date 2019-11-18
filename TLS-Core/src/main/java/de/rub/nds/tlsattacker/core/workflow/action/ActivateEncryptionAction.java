/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySetGenerator;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ActivateEncryptionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ActivateEncryptionAction() {
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ActivateEncryptionAction;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getConnectionAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }

        KeySet keySet;
        try {
            keySet = KeySetGenerator.generateKeySet(tlsContext);
        } catch (NoSuchAlgorithmException | CryptoException ex) {
            throw new UnsupportedOperationException("The specified Algorithm is not supported", ex);
        }
        LOGGER.debug("Setting new Cipher in RecordLayer");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        tlsContext.getRecordLayer().setRecordCipher(recordCipher);

        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.setReadSequenceNumber(0);
        tlsContext.getRecordLayer().updateEncryptionCipher();
        tlsContext.setWriteSequenceNumber(0);

        LOGGER.info("Activated Encryption/Decryption");
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

}
