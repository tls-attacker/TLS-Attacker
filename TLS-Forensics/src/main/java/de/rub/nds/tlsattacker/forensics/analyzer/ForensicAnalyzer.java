/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.forensics.analyzer;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.computations.KeyExchangeComputations;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class tries to reconstruct WorkflowTraces
 *
 */
public class ForensicAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger();

    private ConnectionEndType connectionEndType;

    public ForensicAnalyzer() {
    }

    public WorkflowTrace getRealWorkflowTrace(WorkflowTrace executedWorkflow, BigInteger rsaPrivateKey)
            throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        if (!isSupported(executedWorkflow)) {
            return null;
        }
        WorkflowTrace reconstructed = new WorkflowTrace();
        int tracePosition = 0; // The action we are currently looking at.
        State state = new State(); // initialise an empty state
        TlsContext context = state.getTlsContext();
        if (rsaPrivateKey != null) {
            context.getConfig().setDefaultClientRSAPrivateKey(rsaPrivateKey);
            context.getConfig().setDefaultServerRSAPrivateKey(rsaPrivateKey);
        }
        context.setRecordLayer(new TlsRecordLayer(context));
        adjustPrivateKeys(state, executedWorkflow);
        // Try to determin if the trace was a client or server trace
        connectionEndType = ConnectionEndType.CLIENT;
        if (executedWorkflow.getTlsActions().size() > 0) {
            if (!(executedWorkflow.getTlsActions().get(0) instanceof SendingAction)) {
                connectionEndType = ConnectionEndType.SERVER;
            }
        }
        while (tracePosition < executedWorkflow.getTlsActions().size()) {
            boolean sending;
            List<TlsAction> joinedActions;
            if (executedWorkflow.getTlsActions().get(tracePosition) instanceof SendingAction) {
                joinedActions = joinSendActions(tracePosition, executedWorkflow);
                sending = true;
            } else {
                joinedActions = joinReceiveActions(tracePosition, executedWorkflow);
                sending = false;
            }
            byte[] joinedRecordBytes = joinRecordBytes(joinedActions);
            tracePosition += joinedActions.size();
            if (joinedRecordBytes.length == 0) {
                continue;
            }
            ReceiveMessageHelper helper = new ReceiveMessageHelper();
            if (sending) {
                context.setTalkingConnectionEndType(connectionEndType);
            } else {
                context.setTalkingConnectionEndType(connectionEndType.getPeer());
            }
            if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {
                context.setConnection(new InboundConnection());
            } else {
                context.setConnection(new OutboundConnection());
            }

            context.setReversePrepareAfterParse(sending);
            MessageActionResult parsedMessageResult = helper.handleReceivedBytes(joinedRecordBytes, context);
            if (sending) {
                SendAction reconstructedAction = new SendAction(parsedMessageResult.getMessageList());
                reconstructedAction.setRecords(parsedMessageResult.getRecordList());
                reconstructed.addTlsAction(reconstructedAction);
            } else {
                GenericReceiveAction reconstructedAction = new GenericReceiveAction();
                reconstructedAction.setRecords(parsedMessageResult.getRecordList());
                reconstructedAction.setMessages(parsedMessageResult.getMessageList());
                reconstructed.addTlsAction(reconstructedAction);
            }
        }

        return reconstructed;
    }

    public WorkflowTrace getRealWorkflowTrace(WorkflowTrace executedWorkflow) throws IOException {
        return getRealWorkflowTrace(executedWorkflow, null);
    }

    public byte[] joinRecordBytes(List<TlsAction> sendActions) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (TlsAction action : sendActions) {
            if (action.isExecuted()) {
                if (action instanceof MessageAction) {
                    MessageAction msgAction = (MessageAction) action;
                    List<AbstractRecord> records = msgAction.getRecords();
                    for (AbstractRecord record : records) {
                        try {
                            if (record.getCompleteRecordBytes() != null
                                    && record.getCompleteRecordBytes().getValue() != null) {
                                stream.write(record.getCompleteRecordBytes().getValue());
                            } else {
                                LOGGER.warn("Something went terribly wrong. The record does not contain complete record bytes");
                            }
                        } catch (IOException ex) {
                            LOGGER.warn("Could not write to ByteArrayOutputStream.", ex);
                        }
                    }
                } else {
                    throw new IllegalArgumentException("List contains non MessageActions");
                }
            }
        }
        return stream.toByteArray();
    }

    public boolean isSupported(WorkflowTrace trace) {
        for (TlsAction action : trace.getTlsActions()) {
            if (!(action instanceof SendAction || action instanceof ReceiveAction || action instanceof GenericReceiveAction)) {
                return false;
            }
        }
        return true;
    }

    public List<TlsAction> joinSendActions(int position, WorkflowTrace trace) {
        List<TlsAction> joinedActions = new LinkedList<>();
        for (int i = position; i < trace.getTlsActions().size(); i++) {
            TlsAction action = trace.getTlsActions().get(i);
            if (action instanceof SendAction) {
                joinedActions.add(action);
            } else {
                return joinedActions;
            }
        }
        return joinedActions;
    }

    public List<TlsAction> joinReceiveActions(int position, WorkflowTrace trace) {
        List<TlsAction> joinedActions = new LinkedList<>();
        for (int i = position; i < trace.getTlsActions().size(); i++) {
            TlsAction action = trace.getTlsActions().get(i);
            if (action instanceof ReceiveAction || action instanceof GenericReceiveAction) {
                joinedActions.add(action);
            } else {
                return joinedActions;
            }
        }
        return joinedActions;
    }

    public void adjustPrivateKeys(State state, WorkflowTrace executedTrace) {
        Config config = state.getConfig();
        List<SendingAction> sendingActions = executedTrace.getSendingActions();
        for (SendingAction action : sendingActions) {
            for (ProtocolMessage message : action.getSendMessages()) {
                for (ModifiableVariableHolder holder : message.getAllModifiableVariableHolders()) {
                    if (holder instanceof KeyExchangeComputations) {
                        ((KeyExchangeComputations) holder).setSecretsInConfig(config);
                    }
                }
            }
        }
    }
}
