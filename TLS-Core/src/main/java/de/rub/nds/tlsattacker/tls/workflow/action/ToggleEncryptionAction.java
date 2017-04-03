/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ToggleEncryptionAction extends TLSAction {

    public ToggleEncryptionAction() {
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException {
        // tlsContext.getRecordHandler().setEncryptSending(!tlsContext.getRecordHandler().isEncryptSending());
        executed = true;
        throw new UnsupportedOperationException("Currently not supported");
    }

    @Override
    public void reset() {
        executed = false;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ToggleEncryptionAction;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        return hash;
    }

}
