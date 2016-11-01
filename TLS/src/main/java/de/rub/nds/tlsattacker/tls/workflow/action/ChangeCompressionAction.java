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

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ChangeCompressionAction extends TLSAction {
    private CompressionMethod newValue = null;
    private CompressionMethod oldValue = null;

    public ChangeCompressionAction(CompressionMethod newValue) {
	super();
	this.newValue = newValue;
    }

    public ChangeCompressionAction() {
    }

    public void setNewValue(CompressionMethod newValue) {
	this.newValue = newValue;
    }

    public CompressionMethod getNewValue() {
	return newValue;
    }

    public CompressionMethod getOldValue() {
	return oldValue;
    }

    @Override
    public void execute(TlsContext tlsContext, ActionExecutor executor) throws WorkflowExecutionException, IOException {
	if (executed) {
	    throw new WorkflowExecutionException("Action already executed!");
	}
	oldValue = tlsContext.getCompressionMethod();
	tlsContext.setCompressionMethod(newValue);
        executed = true;
    }

    @Override
    public void reset() {
	oldValue = null;
        executed = false;
    }

}
