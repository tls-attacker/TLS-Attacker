/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.RecordHandler;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.SimpleTransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class GenericWorkflowExecutor implements WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(GenericWorkflowExecutor.class);

    /**
     * indicates if the workflow was already executed
     */
    protected boolean executed = false;

    protected final TlsContext tlsContext;

    protected WorkflowContext workflowContext;
    private ExecutorType type;

    public GenericWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext, ExecutorType type) {
	this.tlsContext = tlsContext;
	tlsContext.setRecordHandler(new RecordHandler(tlsContext));
	tlsContext.setTransportHandler(transportHandler);
	this.workflowContext = new WorkflowContext();
	this.type = type;
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
	if (executed) {
	    throw new IllegalStateException("The workflow has already been" + " executed. Create a new Workflow.");
	}
	executed = true;
	ActionExecutor actionExecutor = ActionExecutorFactory.createActionExecutor(tlsContext, type);
	List<TLSAction> tlsActions = tlsContext.getWorkflowTrace().getTLSActions();
	try {
	    while (workflowContext.getActionPointer() < tlsActions.size() && workflowContext.isProceedWorkflow()) {
		TLSAction action = tlsActions.get(workflowContext.getActionPointer());
		action.execute(tlsContext, actionExecutor);
		workflowContext.incrementActionPointer();
	    }
	} catch (WorkflowExecutionException | IOException e) {
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	}
    }
}
