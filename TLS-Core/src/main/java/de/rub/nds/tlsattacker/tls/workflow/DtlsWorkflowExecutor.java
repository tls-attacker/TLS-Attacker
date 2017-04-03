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
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.DTLSActionExecutor;
import de.rub.nds.tlsattacker.tls.workflow.action.executor.ExecutorType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsWorkflowExecutor extends WorkflowExecutor {

    public DtlsWorkflowExecutor(TlsContext context) {
        super(ExecutorType.DTLS, context);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    // private static final Logger LOGGER =
    // LogManager.getLogger(DtlsWorkflowExecutor.class);
    //
    // private final WorkflowTrace workflowTrace;
    // private final DTLSActionExecutor actionExecutor;
    //
    // public DtlsWorkflowExecutor(TlsContext tlsContext) {
    // super(ExecutorType.DTLS, tlsContext);
    // tlsContext.setTransportHandler(createTransportHandler());
    // tlsContext.setRecordHandler(new DtlsRecordHandler(tlsContext));
    // actionExecutor = new DTLSActionExecutor(tlsContext);
    // workflowTrace = this.context.getWorkflowTrace();
    //
    // if (tlsContext.getTransportHandler() == null ||
    // tlsContext.getRecordHandler() == null) {
    // throw new
    // ConfigurationException("The WorkflowExecutor was not configured properly");
    // }
    // }
    //
    // @Override
    // public void executeWorkflow() throws WorkflowExecutionException {
    // WorkflowContext workflowContext = new WorkflowContext();
    // List<TLSAction> actions = workflowTrace.getTLSActions();
    // try {
    // // This construct is necessary since some actions have to be
    // // rewinded?
    // while (workflowContext.getActionPointer() < actions.size() &&
    // workflowContext.isProceedWorkflow()) {
    // TLSAction action = actions.get(workflowContext.getActionPointer());
    // action.execute(context, actionExecutor);
    // workflowContext.incrementActionPointer();
    // }
    // } catch (WorkflowExecutionException | IOException e) {
    // e.printStackTrace();
    // throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
    // }
    // context.getTransportHandler().closeConnection();
    //
    // }
    //
    // public DTLSActionExecutor getActionExecutor() {
    // return actionExecutor;
    // }

}
