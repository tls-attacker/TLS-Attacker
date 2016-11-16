/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.certificate.CertificateAdapter;
import de.rub.nds.tlsattacker.certificate.X509CertificateObjectAdapter;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ChangeServerCertificateAction extends TLSAction {

    @XmlJavaTypeAdapter(CertificateAdapter.class)
    private Certificate newValue = null;
    @XmlJavaTypeAdapter(X509CertificateObjectAdapter.class)
    private X509CertificateObject x509newValue = null;
    @XmlJavaTypeAdapter(CertificateAdapter.class)
    private Certificate oldValue = null;
    @XmlJavaTypeAdapter(X509CertificateObjectAdapter.class)
    private X509CertificateObject x509oldValue = null;

    // TODO I really like to add a ServerCertificateStructure constructor, but
    // the
    // Struct is not in the TLS package, perhaps i should mitigate it here for
    // now we dont serialize the certs
    public ChangeServerCertificateAction(Certificate newValue, X509CertificateObject x509newValue) {
        super();
        this.newValue = newValue;
        this.x509newValue = x509newValue;
    }

    private ChangeServerCertificateAction() {
        // Private Constructor for JAXB Magic
    }

    public Certificate getNewValue() {
        return newValue;
    }

    public Certificate getOldValue() {
        return oldValue;
    }

    public X509CertificateObject getX509newValue() {
        return x509newValue;
    }

    public X509CertificateObject getX509oldValue() {
        return x509oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException {
        if (executed) {
            throw new WorkflowExecutionException("Action already executed!");
        }
        oldValue = tlsContext.getServerCertificate();
        tlsContext.setServerCertificate(newValue);
        x509oldValue = tlsContext.getX509ServerCertificateObject();
        tlsContext.setX509ServerCertificateObject(x509newValue);
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
        hash = 29 * hash + Objects.hashCode(this.newValue);
        hash = 29 * hash + Objects.hashCode(this.x509newValue);
        hash = 29 * hash + Objects.hashCode(this.oldValue);
        hash = 29 * hash + Objects.hashCode(this.x509oldValue);
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
        final ChangeServerCertificateAction other = (ChangeServerCertificateAction) obj;
        if (!Objects.equals(this.newValue, other.newValue)) {
            return false;
        }
        if (!Objects.equals(this.x509newValue, other.x509newValue)) {
            return false;
        }
        if (!Objects.equals(this.oldValue, other.oldValue)) {
            return false;
        }
        if (!Objects.equals(this.x509oldValue, other.x509oldValue)) {
            return false;
        }
        return true;
    }

}
