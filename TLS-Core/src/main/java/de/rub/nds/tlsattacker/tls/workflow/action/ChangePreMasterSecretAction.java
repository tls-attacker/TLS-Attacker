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
import static de.rub.nds.tlsattacker.tls.workflow.action.TLSAction.LOGGER;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.modifiablevariable.util.ByteArrayAdapter;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangePreMasterSecretAction extends TLSAction {
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] newValue = null;
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] oldValue = null;

    public ChangePreMasterSecretAction(byte[] newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangePreMasterSecretAction() {
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
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getPreMasterSecret();
        tlsContext.setPreMasterSecret(newValue);
        LOGGER.info("Changed PreMasterSecret from " + ArrayConverter.bytesToHexString(oldValue) + " to "
                + ArrayConverter.bytesToHexString(newValue));
        setExecuted(true);
    }

    @Override
    public void reset() {
        oldValue = null;
        setExecuted(null);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 19 * hash + Arrays.hashCode(this.newValue);
        hash = 19 * hash + Arrays.hashCode(this.oldValue);
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
        final ChangePreMasterSecretAction other = (ChangePreMasterSecretAction) obj;
        if (!Arrays.equals(this.newValue, other.newValue)) {
            return false;
        }
        return Arrays.equals(this.oldValue, other.oldValue);
    }

}
