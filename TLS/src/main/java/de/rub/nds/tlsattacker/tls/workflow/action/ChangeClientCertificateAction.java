/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.io.IOException;
import javax.xml.bind.annotation.XmlTransient;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeClientCertificateAction extends TLSAction {
    @XmlTransient
    private Certificate newValue = null;
    @XmlTransient
    private X509CertificateObject x509newValue = null;
    @XmlTransient
    private Certificate oldValue = null;
    @XmlTransient
    private X509CertificateObject x509oldValue = null;

    // TODO I really like to add a ClientCertificateStructure constructor, but
    // the
    // Struct is not in the TLS package, perhaps i should mitigate it here for
    // now we dont serialize the certs
    public ChangeClientCertificateAction(Certificate newValue, X509CertificateObject x509newValue) {
	super();
	this.newValue = newValue;
	this.x509newValue = x509newValue;
    }

    public ChangeClientCertificateAction() {
    }

    public void setOldValue(Certificate oldValue) {
	this.oldValue = oldValue;
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
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException, IOException {
	if (executed) {
	    throw new WorkflowExecutionException("Action already executed!");
	}
	oldValue = tlsContext.getClientCertificate();
	x509oldValue = tlsContext.getX509ClientCertificateObject();
	tlsContext.setClientCertificate(newValue);
	tlsContext.setX509ClientCertificateObject(x509newValue);
        executed = true;
    }

    @Override
    public void reset() {
	oldValue = null;
        executed = false;
    }

}
