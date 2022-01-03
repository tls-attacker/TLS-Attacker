/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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

public abstract class ActivateCryptoAction extends ConnectionBoundAction {
    protected static final Logger LOGGER = LogManager.getLogger();

    public ActivateCryptoAction() {

    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ActivateEncryptionAction;
    }

    protected abstract void activateCrypto(TlsContext tlsContext, RecordCipher recordCipher);

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
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet);
        activateCrypto(tlsContext, recordCipher);
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
