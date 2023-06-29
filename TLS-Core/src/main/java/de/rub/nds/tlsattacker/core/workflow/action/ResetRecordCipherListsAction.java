/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.state.State;

/**
 * This action removes the most recent ciphers from the encryptor and decryptor. The most-recent
 * cipher used to encrypt and decrypt records will thus be an older one with its state (if
 * applicable) kept in place
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
    public void execute(State state) throws ActionExecutionException {
        TlsContext context = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        RecordLayer recordLayer = context.getRecordLayer();
        if (recordLayer != null) {
            recordLayer.getEncryptor().removeCiphers(toRemoveEncryptor);
            recordLayer.getDecryptor().removeCiphers(toRemoveDecryptor);
        } else {
            LOGGER.warn("The current context does not have a Record Layer");
        }
        setExecuted(true);
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
