/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.annotation.XmlTransient;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCipherSuiteAction extends TLSAction {
    private CipherSuite newValue = null;
    private CipherSuite oldValue = null;

    public ChangeCipherSuiteAction(CipherSuite newValue) {
	// TODO can be better implemented with generics?
	super();
	this.newValue = newValue;
    }

    public ChangeCipherSuiteAction() {
    }

    public CipherSuite getNewValue() {
	return newValue;
    }

    public void setNewValue(CipherSuite newValue) {
	this.newValue = newValue;
    }

    public CipherSuite getOldValue() {
	return oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException{
        try {
            if (executed) {
                throw new WorkflowExecutionException("Action already executed!");
            }
            oldValue = tlsContext.getSelectedCipherSuite();
            tlsContext.setSelectedCipherSuite(newValue);
            tlsContext.getRecordHandler().getRecordCipher().init();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new UnsupportedOperationException(ex);
        }
    }

    @Override
    public void reset() {
	oldValue = null;
    }

}
