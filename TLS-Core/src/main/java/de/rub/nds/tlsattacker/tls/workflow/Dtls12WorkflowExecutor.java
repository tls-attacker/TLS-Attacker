/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.dtls.record.DtlsRecordHandler;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.workflow.GenericWorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.DTLSActionExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class Dtls12WorkflowExecutor extends GenericWorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(Dtls12WorkflowExecutor.class);

    private final WorkflowTrace workflowTrace;
    private final DTLSActionExecutor actionExecutor;

    public Dtls12WorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
        super(transportHandler, tlsContext, ExecutorType.DTLS);
        tlsContext.setTransportHandler(transportHandler);
        tlsContext.setRecordHandler(new DtlsRecordHandler(tlsContext));
        actionExecutor = new DTLSActionExecutor(tlsContext);
        workflowTrace = this.tlsContext.getWorkflowTrace();

        if (tlsContext.getTransportHandler() == null || tlsContext.getRecordHandler() == null) {
            throw new ConfigurationException("The WorkflowExecutor was not configured properly");
        }
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        if (executed) {
            throw new IllegalStateException("The workflow has already been executed. Create a new Workflow.");
        }
        executed = true;

        List<TLSAction> actions = workflowTrace.getTLSActions();
        try {
            while (workflowContext.getActionPointer() < actions.size() && workflowContext.isProceedWorkflow()) {
                TLSAction action = actions.get(workflowContext.getActionPointer());
                action.execute(tlsContext, actionExecutor);
                workflowContext.incrementActionPointer();
            }
        } catch (WorkflowExecutionException | IOException e) {
            e.printStackTrace();
            throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
        }
    }

    public DTLSActionExecutor getActionExecutor() {
        return actionExecutor;
    }

}
