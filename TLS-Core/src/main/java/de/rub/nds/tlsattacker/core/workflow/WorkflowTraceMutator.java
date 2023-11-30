/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillAction;
import de.rub.nds.tlsattacker.core.workflow.action.StaticReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.StaticSendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A class to manipulate statically configured actions in workflow traces. */
public class WorkflowTraceMutator {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void replaceMessagesInList(
            List<ProtocolMessage> messageList,
            ProtocolMessageType type,
            ProtocolMessage replaceMessage) {
        if (replaceMessage != null) {
            messageList.replaceAll(
                    message -> {
                        if (message.getProtocolMessageType() == type) {
                            return replaceMessage;
                        }
                        return message;
                    });
        } else {
            messageList.removeIf(
                    message -> {
                        if (message.getProtocolMessageType() == type) {
                            return true;
                        }
                        return false;
                    });
        }
    }

    private static void replaceMessagesInList(
            List<ProtocolMessage> messageList,
            HandshakeMessageType type,
            ProtocolMessage replaceMessage) {
        if (replaceMessage != null) {
            messageList.replaceAll(
                    message -> {
                        if (message instanceof HandshakeMessage
                                && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                            return replaceMessage;
                        }
                        return message;
                    });
        } else {
            messageList.removeIf(
                    message -> {
                        if (message instanceof HandshakeMessage
                                && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                            return true;
                        }
                        return false;
                    });
        }
    }

    public static void replaceStaticSendingMessage(
            WorkflowTrace trace, ProtocolMessageType type, ProtocolMessage replacementMessage) {
        List<StaticSendingAction> sendingActions =
                WorkflowTraceConfigurationUtil.getStaticSendingActionsWithConfiguration(
                        trace, type);
        List<StaticSendingAction> deleteActions = new ArrayList<>();
        for (StaticSendingAction action : sendingActions) {
            List<ProtocolMessage> messages = action.getConfiguredList(ProtocolMessage.class);
            replaceMessagesInList(messages, type, replacementMessage);
            if (messages.size() == 0) {
                deleteActions.add(action);
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void replaceStaticSendingMessage(
            WorkflowTrace trace, HandshakeMessageType type, HandshakeMessage replacementMessage) {
        List<StaticSendingAction> sendingActions =
                WorkflowTraceConfigurationUtil.getStaticSendingActionsWithConfiguration(
                        trace, type);
        List<StaticSendingAction> deleteActions = new ArrayList<>();
        for (StaticSendingAction action : sendingActions) {
            List<ProtocolMessage> messages = action.getConfiguredList(ProtocolMessage.class);
            replaceMessagesInList(messages, type, replacementMessage);
            if (messages.size() == 0) {
                deleteActions.add(action);
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void deleteSendingMessage(WorkflowTrace trace, ProtocolMessageType type) {
        replaceStaticSendingMessage(trace, type, null);
    }

    public static void deleteSendingMessage(WorkflowTrace trace, HandshakeMessageType type) {
        replaceStaticSendingMessage(trace, type, null);
    }

    public static void replaceReceivingMessage(
            @Nonnull WorkflowTrace trace,
            @Nonnull ProtocolMessageType type,
            @Nullable ProtocolMessage replaceMessage)
            throws WorkflowTraceMutationException {
        List<StaticReceivingAction> receivingActions =
                WorkflowTraceConfigurationUtil.getStaticReceivingActionsWithConfiguration(
                        trace, type);
        List<StaticReceivingAction> deleteActions = new ArrayList<>();
        for (StaticReceivingAction action : receivingActions) {
            if (action instanceof ReceiveAction) {
                List<ProtocolMessage> messages = ((ReceiveAction) action).getExpectedMessages();
                replaceMessagesInList(messages, type, replaceMessage);
                if (messages.isEmpty()) {
                    deleteActions.add(action);
                }
            } else if (action instanceof ReceiveTillAction) {
                ProtocolMessage message = ((ReceiveTillAction) action).getWaitTillMessage();
                if (message.getProtocolMessageType() == type) {
                    if (replaceMessage == null) {
                        throw new WorkflowTraceMutationException(
                                "ReceiveTillAction cannot be deleted, because this will probably break your workflow.");
                    }
                    ((ReceiveTillAction) action).setWaitTillMessage(replaceMessage);
                }
            } else {
                throw new WorkflowTraceMutationException(
                        "Unsupported ReceivingAction, could not mutate workflow.");
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void replaceReceivingMessage(
            @Nonnull WorkflowTrace trace,
            @Nonnull HandshakeMessageType type,
            @Nullable ProtocolMessage replaceMessage)
            throws WorkflowTraceMutationException {
        List<StaticReceivingAction> receivingActions =
                WorkflowTraceConfigurationUtil.getStaticReceivingActionsWithConfiguration(
                        trace, type);
        List<StaticReceivingAction> deleteActions = new ArrayList<>();
        for (StaticReceivingAction action : receivingActions) {
            if (action instanceof ReceiveAction) {
                List<ProtocolMessage> messages = ((ReceiveAction) action).getExpectedMessages();
                replaceMessagesInList(messages, type, replaceMessage);
                if (messages.isEmpty()) {
                    deleteActions.add(action);
                }
            } else if (action instanceof ReceiveTillAction) {
                ProtocolMessage message = ((ReceiveTillAction) action).getWaitTillMessage();
                if (message.isHandshakeMessage()
                        && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    if (replaceMessage == null) {
                        throw new WorkflowTraceMutationException(
                                "ReceiveTillAction cannot be deleted, because this will probably break your workflow.");
                    }
                    ((ReceiveTillAction) action).setWaitTillMessage(replaceMessage);
                }
            } else {
                throw new WorkflowTraceMutationException(
                        "Unsupported ReceivingAction, could not mutate workflow.");
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void deleteReceivingMessage(WorkflowTrace trace, ProtocolMessageType type)
            throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    public static void deleteReceivingMessage(WorkflowTrace trace, HandshakeMessageType type)
            throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    private static void truncate(
            WorkflowTrace trace,
            Object type,
            WorkflowTruncationMode mode,
            Boolean sending,
            Boolean untilLast) {
        TlsAction action = null;
        if (untilLast != null && untilLast == true) {
            if (type instanceof HandshakeMessageType) {
                if (sending) {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getLastStaticConfiguredSendAction(
                                                    trace, (HandshakeMessageType) type);
                } else {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getLastStaticConfiguredReceiveAction(
                                                    trace, (HandshakeMessageType) type);
                }
            } else if (type instanceof ProtocolMessageType) {
                if (sending) {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getLastStaticConfiguredSendAction(
                                                    trace, (ProtocolMessageType) type);
                } else {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getLastStaticConfiguredReceiveAction(
                                                    trace, (ProtocolMessageType) type);
                }
            }
        } else {
            if (type instanceof HandshakeMessageType) {
                if (sending) {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getFirstStaticConfiguredSendAction(
                                                    trace, (HandshakeMessageType) type);
                } else {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getFirstStaticConfiguredReceiveAction(
                                                    trace, (HandshakeMessageType) type);
                }
            } else if (type instanceof ProtocolMessageType) {
                if (sending) {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getFirstStaticConfiguredSendAction(
                                                    trace, (ProtocolMessageType) type);
                } else {
                    action =
                            (TlsAction)
                                    WorkflowTraceConfigurationUtil
                                            .getFirstStaticConfiguredReceiveAction(
                                                    trace, (ProtocolMessageType) type);
                }
            }
        }
        if (action == null) {
            return;
        }

        int messageIndex = -1;
        int actionIndex = trace.getTlsActions().indexOf(action);
        List<ProtocolMessage> messages = new ArrayList<>();
        if (action instanceof StaticSendingAction) {
            messages = ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class);
        } else if (action instanceof StaticReceivingAction) {
            messages = ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class);
        }

        for (ProtocolMessage message : messages) {
            if (type instanceof HandshakeMessageType) {
                if (!(message instanceof HandshakeMessage)) {
                    continue;
                }
                if (((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    messageIndex = getIndexOfIdenticalMessage(messages, message);
                    if (messageIndex == 0 && mode == WorkflowTruncationMode.AT) {
                        actionIndex -= 1;
                    }
                    break;
                }
            } else {
                if (message.getProtocolMessageType() == type) {
                    messageIndex = getIndexOfIdenticalMessage(messages, message);
                    if (messageIndex == 0 && mode == WorkflowTruncationMode.AT) {
                        actionIndex -= 1;
                    }
                    break;
                }
            }
        }

        int offset = 0;
        if (mode == WorkflowTruncationMode.AFTER) {
            offset = 1;
        }

        // is false for example for dynamic send actions
        if (messages.size() > 0) {
            if (messages.size() > messageIndex + offset) {
                messages.subList(messageIndex + offset, messages.size()).clear();
            }
        } else if (mode == WorkflowTruncationMode.AT) {
            actionIndex -= 1;
        }

        List<TlsAction> workflowActions = trace.getTlsActions();
        if (workflowActions.size() > actionIndex + 1) {
            workflowActions.subList(actionIndex + 1, workflowActions.size()).clear();
        }
    }

    public static void truncateAt(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, null, untilLast);
    }

    public static void truncateAt(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, null, untilLast);
    }

    public static void truncateAt(
            WorkflowTrace trace, HandshakeMessageType type, Boolean sending, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateAt(
            WorkflowTrace trace, ProtocolMessageType type, Boolean sending, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateSendingAt(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateSendingAt(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateReceivingAt(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateReceivingAt(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateAfter(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, null, untilLast);
    }

    public static void truncateAfter(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, null, untilLast);
    }

    public static void truncateSendingAfter(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateSendingAfter(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateReceivingAfter(
            WorkflowTrace trace, HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, false, untilLast);
    }

    public static void truncateReceivingAfter(
            WorkflowTrace trace, ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, false, untilLast);
    }

    private static int getIndexOfIdenticalMessage(
            List<ProtocolMessage> collection, ProtocolMessage message) {
        if (collection != null) {
            for (int i = 0; i < collection.size(); i++) {
                if (collection.get(i) == message) {
                    return i;
                }
            }
        }
        return -1;
    }
}
