/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.dtls.workflow.Dtls12WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class WorkflowExecutorFactory {

    public static WorkflowExecutor createWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	WorkflowExecutor we = null;
	switch (tlsContext.getProtocolVersion()) {
	    case TLS10:
	    case TLS11:
	    case TLS12:
		we = new GenericWorkflowExecutor(transportHandler, tlsContext, ExecutorType.TLS);
		return we;
	    case DTLS12:
		we = new Dtls12WorkflowExecutor(transportHandler, tlsContext);
		return we;
	    default:
		throw new UnsupportedOperationException("not yet implemented");
	}
    }
}
