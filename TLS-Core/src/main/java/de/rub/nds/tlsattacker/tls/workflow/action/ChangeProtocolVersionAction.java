/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.io.IOException;
import java.util.Objects;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeProtocolVersionAction extends TLSAction {

    private ProtocolVersion newValue;
    private ProtocolVersion oldValue = null;

    public ChangeProtocolVersionAction(ProtocolVersion newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangeProtocolVersionAction() {
    }

    public void setNewValue(ProtocolVersion newValue) {
        this.newValue = newValue;
    }

    public ProtocolVersion getNewValue() {
        return newValue;
    }

    public ProtocolVersion getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException {
        if (executed) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getConfig().getProtocolVersion();
        tlsContext.getConfig().setProtocolVersion(newValue);
        executed = true;
    }

    @Override
    public void reset() {
        oldValue = null;
        executed = false;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 83 * hash + Objects.hashCode(this.newValue);
        hash = 83 * hash + Objects.hashCode(this.oldValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ChangeProtocolVersionAction other = (ChangeProtocolVersionAction) obj;
        if (this.newValue != other.newValue) {
            return false;
        }
        if (this.oldValue != other.oldValue) {
            return false;
        }
        return true;
    }

}
