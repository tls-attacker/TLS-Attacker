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
import de.rub.nds.tlsattacker.core.state.State;

public abstract class DeactivateCryptoAction extends ConnectionBoundAction {

    public DeactivateCryptoAction() {}

    protected abstract void deactivateCrypto(TlsContext tlsContext);

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }
        deactivateCrypto(tlsContext);
        setExecuted(true);
    }

    @Override
    public void reset() {
        setExecuted(false);
        setExecuted(null);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof DeactivateEncryptionAction && super.equals(o);
    }

    @Override
    public int hashCode() {
        return 17 * super.hashCode();
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
