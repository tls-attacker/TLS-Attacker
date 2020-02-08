/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.task;

import de.rub.nds.tlsattacker.attacks.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsattacker.attacks.cca.vector.CcaVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CcaDelegate;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class CcaTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CcaVector ccaVector;
    private State state;
    private final Config tlsConfig;
    private final CcaDelegate ccaDelegate;

    public CcaTask(CcaVector ccaVector, Config tlsConfig, CcaDelegate ccaDelegate, int reexecutions) {
        super(reexecutions);
        this.ccaVector = ccaVector;
        this.tlsConfig = tlsConfig;
        this.ccaDelegate = ccaDelegate;
    }

    public CcaTask(CcaVector ccaVector, Config tlsConfig, CcaDelegate ccaDelegate, long additionalTimeout, boolean increasingTimeout, int reexecutions,
                   long additionalTcpTimeout) {
        super(reexecutions, additionalTimeout, increasingTimeout, additionalTcpTimeout);
        this.ccaVector = ccaVector;
        this.tlsConfig = tlsConfig;
        this.ccaDelegate = ccaDelegate;
    }

    private State prepareState() {
        tlsConfig.setDefaultClientSupportedCiphersuites(ccaVector.getCipherSuite());
        tlsConfig.setHighestProtocolVersion(ccaVector.getProtocolVersion());
        tlsConfig.setEarlyStop(true);
        tlsConfig.setStopReceivingAfterFatal(true);
        tlsConfig.setStopActionsAfterFatal(true);
        tlsConfig.setStopActionsAfterIOException(true);
        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaDelegate, ccaVector.getCcaWorkflowType(), ccaVector.getCcaCertificateType());
        State state = new State(tlsConfig, trace);
        return state;
    }

    @Override
    public void execute() {
        state = prepareState();
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            executor.executeWorkflow();

        } finally {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    public CcaVector getCcaVector() {
        return ccaVector;
    }

    public State getState() { return  state; }

    @Override
    public void reset() {
        state.reset();
    }

}
