/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.task;

import de.rub.nds.tlsattacker.attacks.exception.FingerprintExtractionException;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FingerPrintTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private State state;

    private ResponseFingerprint fingerprint;

    public FingerPrintTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    public FingerPrintTask(State state, long additionalTimeout, boolean increasingTimeout, int reexecutions,
            long additionalTcpTimeout) {
        super(reexecutions, additionalTimeout, increasingTimeout, additionalTcpTimeout);
        this.state = state;
    }

    @Override
    public boolean execute() {
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            executor.executeWorkflow();

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                return false;
            }
            fingerprint = ResponseExtractor.getFingerprint(state);

            if (fingerprint == null) {
                return false;
            }
            return true;
        } finally {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    public State getState() {
        return state;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public void reset() {
        state.reset();
    }

    public void setState(State state) {
        this.state = state;
    }

    public void setFingerprint(ResponseFingerprint fingerprint) {
        this.fingerprint = fingerprint;
    }

}
