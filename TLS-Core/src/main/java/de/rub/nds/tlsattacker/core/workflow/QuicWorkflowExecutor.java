/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.exceptions.SkipActionException;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.impl.QuicPacketLayer;
import de.rub.nds.tlsattacker.core.quic.constants.QuicTransportErrorCodes;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicWorkflowExecutor extends WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger();

    public QuicWorkflowExecutor(State state) {
        super(WorkflowExecutorType.QUIC, state);
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
        // TODO this executor does not use all implemented callbacks
        try {
            initAllLayer();
        } catch (IOException ex) {
            throw new WorkflowExecutionException(
                    "Workflow not executed, could not initialize transport handler: ", ex);
        }
        state.setStartTimestamp(System.currentTimeMillis());
        List<TlsAction> tlsActions = state.getWorkflowTrace().getTlsActions();
        int retransmissions = 0;
        int retransmissionActionIndex = 0;
        for (int i = 0; i < tlsActions.size(); i++) {
            if (i != 0
                    && !(tlsActions.get(i) instanceof ReceivingAction)
                    && (tlsActions.get(i - 1) instanceof ReceivingAction)) {
                retransmissionActionIndex = i;
            }

            if(shouldStopDueToErrorCondition()) {
                break;
            }

            TlsAction action = tlsActions.get(i);

            if (!action.isExecuted()) {
                try {
                    this.executeAction(action, state);
                } catch (SkipActionException ex) {
                    continue;
                }
            } else {
                if (action instanceof SendingAction) {
                    executeRetransmission((SendingAction) action);
                } else if (action instanceof ReceivingAction) {
                    action.reset();
                    try {
                        this.executeAction(action, state);
                    } catch (SkipActionException ex) {
                        continue;
                    }
                }
            }

            if (!action.executedAsPlanned()) {
                if (config.isStopTraceAfterUnexpected()) {
                    LOGGER.debug("Skipping all Actions, action did not execute as planned.");
                    break;
                } else if (retransmissions == config.getMaxUDPRetransmissions()) {
                    LOGGER.debug("Hit max retransmissions, stopping workflow");
                    break;
                } else {
                    i = retransmissionActionIndex - 1;
                    retransmissions++;
                }
            }
        }

        if (config.isFinishWithCloseNotify()) {
            try {
                sendConnectionCloseFrame(
                        state.getContext().getQuicContext().isApplicationSecretsInitialized());
            } catch (IOException ex) {
                LOGGER.warn("Error while sending ConnectionCloseFrame", ex);
            }
        }

        setFinalSocketState();

        if (config.isWorkflowExecutorShouldClose()) {
            closeConnection();
        }

        if (config.isResetWorkflowTracesBeforeSaving()) {
            LOGGER.debug("Resetting WorkflowTrace");
            state.getWorkflowTrace().reset();
        }

        try {
            if (getAfterExecutionCallback() != null) {
                LOGGER.debug("Executing AfterExecutionCallback");
                getAfterExecutionCallback().apply(state);
            }
        } catch (Exception ex) {
            LOGGER.error("Error during AfterExecutionCallback", ex);
        }
    }

    private void sendConnectionCloseFrame(boolean handshakeComplete) throws IOException {
        ConnectionCloseFrame frame =
                new ConnectionCloseFrame(QuicTransportErrorCodes.NO_ERROR.getValue());
        SendAction sendAction =
                new SendAction(state.getWorkflowTrace().getConnections().get(0).getAlias());
        sendAction.setConfiguredQuicFrames(List.of(frame));
        if (handshakeComplete) {
            sendAction.setConfiguredQuicPackets(List.of(new OneRTTPacket()));
        } else {
            sendAction.setConfiguredQuicPackets(List.of(new InitialPacket()));
        }

        sendAction.addActionOption(ActionOption.MAY_FAIL);
        sendAction.execute(state);
    }

    private void executeRetransmission(SendingAction action) {
        if(shouldStopDueToErrorCondition()) return;
        LOGGER.info("Executing retransmission of last sent flight");
        QuicPacketLayer packetLayer =
                (QuicPacketLayer)
                        state.getContext()
                                .getQuicContext()
                                .getLayerStack()
                                .getLayer(QuicPacketLayer.class);
        packetLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration(
                        ImplementedLayers.QUICPACKET, action.getSentQuicPackets()));

        try {
            packetLayer.sendConfiguration();
        } catch (IOException ex) {
            state.getTlsContext().setReceivedTransportHandlerException(true);
            LOGGER.warn("Received IOException during retransmission", ex);
        }
    }

    private boolean shouldStopDueToErrorCondition() {
        if ((config.isStopActionAfterQuicConnCloseFrame() && hasReceivedConnectionCloseframe())) {
            LOGGER.debug(
                    "Skipping all Actions, received ConnectionCloseFrame, StopActionsAfterConnCloseFrame active");
            return true;
        }

        //TODO: Do we need to stop after Alerts in QUIC? They do not exist in QUIC.
        if ((config.isStopActionsAfterFatal() && isReceivedFatalAlert())) {
            LOGGER.debug(
                    "Skipping all Actions, received FatalAlert, StopActionsAfterFatal active");
            return true;
        }
        if ((config.getStopActionsAfterWarning() && isReceivedWarningAlert())) {
            LOGGER.debug(
                    "Skipping all Actions, received Warning Alert, StopActionsAfterWarning active");
            return true;
        }

        if ((config.getStopActionsAfterIOException() && isIoException())) {
            LOGGER.debug(
                    "Skipping all Actions, received IO Exception, StopActionsAfterIOException active");
            return true;
        }
        return false;
    }

        /** Check if a at least one TLS context received a fatal alert. */
    public boolean hasReceivedConnectionCloseframe() {
        for (Context ctx : state.getAllContexts()) {
            if (ctx.getQuicContext().getReceivedConnectionCloseFrame() != null) {
                return true;
            }
        }
        return false;
    }
}
