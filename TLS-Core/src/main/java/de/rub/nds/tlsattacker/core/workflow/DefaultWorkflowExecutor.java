/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerFactory;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutor;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ExecutorType;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DefaultWorkflowExecutor extends WorkflowExecutor {

    public DefaultWorkflowExecutor(TlsContext context) {
        super(ExecutorType.TLS, context);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        context.setTransportHandler(createTransportHandler());
        context.setRecordLayer(RecordLayerFactory.getRecordLayer(context.getConfig().getRecordLayerType(), context));
        context.getWorkflowTrace().reset();
        ActionExecutor actionExecutor = ActionExecutorFactory.getActionExecutor(context.getConfig().getExecutorType(),
                context);
        List<TLSAction> tlsActions = context.getWorkflowTrace().getTLSActions();
        for (TLSAction action : tlsActions) {
            try {
                action.execute(context, actionExecutor);
            } catch (IOException ex) {
                throw new WorkflowExecutionException("Problem while executing Action:" + action.toString(), ex);
            }
        }
        context.getTransportHandler().closeConnection();
        storeTrace();
    }
}
