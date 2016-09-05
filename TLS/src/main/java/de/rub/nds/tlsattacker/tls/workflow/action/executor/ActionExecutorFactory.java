/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow.action.executor;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowContext;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ActionExecutorFactory {
    public static ActionExecutor createActionExecutor(TlsContext context, WorkflowContext workflowContext,
	    ExecutorType type) {
	switch (type) {
	    case DTLS:
		return new DTLSActionExecutor(context); // todo
	    case TLS:
		return new TLSActionExecutor(context, workflowContext);
	    default:
		throw new UnsupportedOperationException("Unknown ExecutorType");

	}
    }
}
