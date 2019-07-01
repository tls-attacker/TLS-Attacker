/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.task;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.attacks.exception.FingerprintExtractionException;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;

public class ClientFingerPrintTask extends FingerPrintTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private ResponseFingerprint fingerprint;

    private Runnable activator;

    private static final ExecutorService activationExecutor = Executors.newSingleThreadExecutor();

    public ClientFingerPrintTask(State state, long additionalTimeout, boolean increasingTimeout, int reexecutions,
            long additionalTcpTimeout, Runnable activator) {
        super(state, additionalTimeout, increasingTimeout, reexecutions, additionalTcpTimeout);

        this.activator = activator;
    }

    @Override
    public void execute() {
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor( getState() );

            activationExecutor.execute( activator );

            executor.executeWorkflow();
            if (!getState().getWorkflowTrace().executedAsPlanned()) {
                throw new FingerprintExtractionException(
                        "Could not extract fingerprint. Not all actions executed as planned");
            }
            fingerprint = ResponseExtractor.getFingerprint(getState());

            if (fingerprint == null) {
                throw new FingerprintExtractionException("Could not extract fingerprint. Fingerprint is null");
            }
        } finally {
            try {
                getState().getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    } 
}
