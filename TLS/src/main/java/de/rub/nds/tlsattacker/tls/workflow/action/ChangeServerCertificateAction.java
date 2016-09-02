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
public class ChangeServerCertificateAction extends TLSAction
{
    private Certificate newValue;
    private X509CertificateObject x509newValue;
    private Certificate oldValue = null;
    private X509CertificateObject x509oldValue = null;
    
    public ChangeServerCertificateAction(Certificate newValue ,X509CertificateObject x509newValue)
    {
        super();
        this.newValue = newValue;
        this.x509newValue = x509newValue;
    }
    public Certificate getNewValue()
    {
        return newValue;
    }

    public Certificate getOldValue()
    {
        return oldValue;
    }
    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException, IOException
    {
        if (executed) {
	    throw new WorkflowExecutionException("Action already executed!");
	}
        oldValue = tlsContext.getServerCertificate();
        tlsContext.setServerCertificate(newValue);
        x509oldValue = tlsContext.getX509ServerCertificateObject();
        tlsContext.setX509ServerCertificateObject(x509newValue);
    }

    @Override
    public void reset()
    {
        oldValue = null;
    }
    
}
