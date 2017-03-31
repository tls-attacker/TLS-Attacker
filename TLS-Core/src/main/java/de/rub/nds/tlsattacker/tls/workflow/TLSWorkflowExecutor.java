/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.record.TlsRecordLayer;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.TLSActionExecutor;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class TLSWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(TLSWorkflowExecutor.class);

    public TLSWorkflowExecutor(TlsContext context) {
        super(ExecutorType.TLS, context);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        context.setTransportHandler(createTransportHandler());
        context.setRecordHandler(new TlsRecordLayer(context));
        context.getWorkflowTrace().reset();
        ActionExecutor actionExecutor = new TLSActionExecutor(context);
        List<TLSAction> tlsActions = context.getWorkflowTrace().getTLSActions();
        for (TLSAction action : tlsActions) {
            try {
                action.execute(context, actionExecutor);
            } catch (IOException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
        }
        context.getTransportHandler().closeConnection();
    }

}
