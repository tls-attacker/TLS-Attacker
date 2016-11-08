/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.io.IOException;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlTransient;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeMasterSecretAction extends TLSAction {

    private byte[] newValue = null;
    private byte[] oldValue = null;

    public ChangeMasterSecretAction(byte[] newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangeMasterSecretAction() {
    }

    public void setNewValue(byte[] newValue) {
        this.newValue = newValue;
    }

    public byte[] getNewValue() {
        return newValue;
    }

    public byte[] getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException {
        if (executed) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getMasterSecret();
        tlsContext.setMasterSecret(newValue);
        executed = true;
    }

    @Override
    public void reset() {
        oldValue = null;
        executed = false;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 71 * hash + Arrays.hashCode(this.newValue);
        hash = 71 * hash + Arrays.hashCode(this.oldValue);
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
        final ChangeMasterSecretAction other = (ChangeMasterSecretAction) obj;
        if (!Arrays.equals(this.newValue, other.newValue)) {
            return false;
        }
        if (!Arrays.equals(this.oldValue, other.oldValue)) {
            return false;
        }
        return true;
    }

}
