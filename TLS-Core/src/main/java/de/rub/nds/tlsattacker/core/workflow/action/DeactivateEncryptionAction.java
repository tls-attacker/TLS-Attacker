/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class DeactivateEncryptionAction extends TLSAction {

    public DeactivateEncryptionAction() {
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(getContextAlias());

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        tlsContext.getRecordLayer().setRecordCipher(new RecordNullCipher(tlsContext));
        tlsContext.getRecordLayer().updateDecryptionCipher();
        tlsContext.getRecordLayer().updateEncryptionCipher();
        LOGGER.info("Deactivated Encryption/Decryption");
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
        setExecuted(null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof DeactivateEncryptionAction;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        return hash;
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
