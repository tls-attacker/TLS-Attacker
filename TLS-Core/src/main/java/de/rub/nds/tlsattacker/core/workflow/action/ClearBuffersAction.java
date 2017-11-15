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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class ClearBuffersAction extends MessageAction {

    public ClearBuffersAction() {
        super();
    }

    public ClearBuffersAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        TlsContext tlsContext = state.getTlsContext(connectionAlias);

        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        tlsContext.getMessageBuffer().clear();
        tlsContext.getRecordBuffer().clear();

        setExecuted(true);
    }

    @Override
    public String toString() {
        return "ClearBuffersAction";
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(null);
    }

}
