/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
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

    private final State state;

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
    public void execute() {
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            executor.executeWorkflow();
            if (!state.getWorkflowTrace().executedAsPlanned()) {
                throw new FingerprintExtractionException(
                        "Could not extract fingerprint. Not all actions executed as planned");
            }
            fingerprint = ResponseExtractor.getFingerprint(state);

            if (fingerprint == null) {
                throw new FingerprintExtractionException("Could not extract fingerprint. Fingerprint is null");
            }
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

}
