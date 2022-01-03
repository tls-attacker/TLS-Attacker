/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayer;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * This action removes the most recent ciphers from the encryptor and decryptor. The most-recent cipher used to encrypt
 * and decrypt records will thus be an older one with its state (if applicable) kept in place
 */
public class ResetRecordCipherListsAction extends ConnectionBoundAction {

    private final int toRemoveEncryptor;
    private final int toRemoveDecryptor;

    public ResetRecordCipherListsAction(int toRemoveEncryptor, int toRemoveDecryptor) {
        this.toRemoveEncryptor = toRemoveEncryptor;
        this.toRemoveDecryptor = toRemoveDecryptor;
    }

    public ResetRecordCipherListsAction() {
        this.toRemoveDecryptor = 1;
        this.toRemoveEncryptor = 1;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext context = state.getTlsContext(getConnectionAlias());
        RecordLayer recordLayer = context.getRecordLayer();
        if (recordLayer instanceof TlsRecordLayer) {
            ((TlsRecordLayer) recordLayer).getEncryptor().removeCiphers(toRemoveEncryptor);
            ((TlsRecordLayer) recordLayer).getDecryptor().removeCiphers(toRemoveDecryptor);
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
