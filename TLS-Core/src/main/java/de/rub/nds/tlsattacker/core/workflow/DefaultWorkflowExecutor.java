/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DefaultWorkflowExecutor extends WorkflowExecutor {

    public DefaultWorkflowExecutor(TlsContext context) {
        super(WorkflowExecutorType.DEFAULT, context);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        if (context.getConfig().isWorkflowExecutorShouldOpen()) {
            context.setTransportHandler(createTransportHandler());
        }
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(context.getConfig().getRecordLayerType(), context));
        context.getWorkflowTrace().reset();
        List<TLSAction> tlsActions = context.getWorkflowTrace().getTlsActions();
        for (TLSAction action : tlsActions) {
            try {
                if (!(context.getConfig().isStopActionsAfterFatal() && context.isReceivedFatalAlert())) {
                    action.execute(context);
                } else {
                    LOGGER.trace("Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
                    break;
                }
            } catch (IOException | PreparationException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
        }
        if (context.getConfig().isWorkflowExecutorShouldClose()) {
            try {
                context.getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.warn("Could not close Connection");
                LOGGER.debug(ex);
            }
        }
        if (context.getConfig().isResetWorkflowtracesBeforeSaving()) {
            context.getWorkflowTrace().reset();
        }
        storeTrace();
    }
}
