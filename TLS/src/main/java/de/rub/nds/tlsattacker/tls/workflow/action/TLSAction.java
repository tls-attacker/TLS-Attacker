/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.io.Serializable;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public abstract class TLSAction implements Serializable {
    protected boolean executed = false;

    public boolean isExecuted() {
        return executed;
    }

    public void setExecuted(boolean executed) {
        this.executed = executed;
    }

    public abstract void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException,
            IOException;

    public boolean isMessageAction() {
        return this instanceof MessageAction;
    }

    public abstract void reset();
}
