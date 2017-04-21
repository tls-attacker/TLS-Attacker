/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.certificate.CertificateAdapter;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import java.util.Objects;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeClientCertificateAction extends TLSAction {
    @XmlJavaTypeAdapter(CertificateAdapter.class)
    private Certificate newValue = null;
    @XmlJavaTypeAdapter(CertificateAdapter.class)
    private Certificate oldValue = null;

    public ChangeClientCertificateAction(Certificate newValue) {
        super();
        this.newValue = newValue;
    }

    public ChangeClientCertificateAction() {
    }

    public Certificate getNewValue() {
        return newValue;
    }

    public Certificate getOldValue() {
        return oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException {
        if (isExecuted()) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getClientCertificate();
        tlsContext.setClientCertificate(newValue);
        LOGGER.info("Changed ClientCertificate");
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
        hash = 13 * hash + Objects.hashCode(this.newValue);
        hash = 13 * hash + Objects.hashCode(this.oldValue);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ChangeClientCertificateAction other = (ChangeClientCertificateAction) obj;
        if (!Objects.equals(this.newValue, other.newValue)) {
            return false;
        }
        return Objects.equals(this.oldValue, other.oldValue);
    }

}
