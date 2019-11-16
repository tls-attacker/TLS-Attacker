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
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.io.IOException;
import java.util.LinkedList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class InvalidCurveTask extends TlsTask {
    
    private static final Logger LOGGER = LogManager.getLogger();
    
    private final int appliedSecret;     

    private final State state;

    private ResponseFingerprint fingerprint;
    
    private Point receivedEcKey;
    
    private boolean resolveTls13CCSdiscrepancy;
    
    public InvalidCurveTask(State state, int reexecutions, int appliedSecret) {
        super(reexecutions);
        this.appliedSecret = appliedSecret;
        this.state = state;
    }

    @Override
    public void reset() {
        getState().reset();
    }

    @Override
    public void execute() {
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor(getState());
            executor.executeWorkflow();
            
            if(resolveTls13CCSdiscrepancy) {
                allowTls13CCS(getState());
            }
            
            if (getState().getTlsContext().getServerEcPublicKey() != null) {
                receivedEcKey = getState().getTlsContext().getServerEcPublicKey();
            }

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                throw new FingerprintExtractionException(
                        "Workflow Trace execution failed before attack vector was sent. No fingerprint extracted.");
            }
            fingerprint = ResponseExtractor.getFingerprint(getState());

            if (getFingerprint() == null) {
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
    
    /**
     * @return the receivedEcKey
     */
    public Point getReceivedEcKey() {
        return receivedEcKey;
    }

    /**
     * @return the resolveTls13CCSdiscrepancy
     */
    public boolean isResolveTls13CCSdiscrepancy() {
        return resolveTls13CCSdiscrepancy;
    }

    /**
     * @param resolveTls13CCSdiscrepancy the resolveTls13CCSdiscrepancy to set
     */
    public void setResolveTls13CCSdiscrepancy(boolean resolveTls13CCSdiscrepancy) {
        this.resolveTls13CCSdiscrepancy = resolveTls13CCSdiscrepancy;
    }
    
    /**
     * Tries to resolve a Workflow Trace conflict when a server sent a
     * CCS message to maintain backward compatibility in a TLS 1.3 handshake
     */
    private void allowTls13CCS(State state)
    {
        ReceiveAction firstServerMessages = null;
        WorkflowTrace trace = state.getWorkflowTrace();
        for(TlsAction action : trace.getTlsActions())
        {
            if(action instanceof ReceiveAction)
            {
                firstServerMessages = (ReceiveAction) action;
                break;
            }
        }
        if (firstServerMessages != null && !firstServerMessages.executedAsPlanned()
                && firstServerMessages.getReceivedMessages().get(1) instanceof ChangeCipherSpecMessage) {
            firstServerMessages.getExpectedMessages().add(1, new ChangeCipherSpecMessage());
            LOGGER.debug("Tried to resolve workflow trace discrepancy for unexpected CCS in TLS 1.3 handshake");
        }
    }       

    /**
     * @return the state
     */
    public State getState() {
        return state;
    }

    /**
     * @return the fingerprint
     */
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    /**
     * @return the appliedSecret
     */
    public int getAppliedSecret() {
        return appliedSecret;
    }
    
}
