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
import de.rub.nds.tlsattacker.core.workflow.action.*;
import java.util.ArrayList;
import java.util.Iterator;
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
            messageList.removeIf(message -> message.getProtocolMessageType() == type);
        }
    }

    private static void replaceMessagesInList(
            List<ProtocolMessage> messageList,
            HandshakeMessageType type,
            ProtocolMessage replacementMessage) {
        if (replacementMessage != null) {
            messageList.replaceAll(
                    message -> {
                        if (message instanceof HandshakeMessage
                                && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                            return replacementMessage;
                        }
                        return message;
                    });
        } else {
            messageList.removeIf(
                    message ->
                            message instanceof HandshakeMessage
                                    && ((HandshakeMessage) message).getHandshakeMessageType()
                                            == type);
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
            if (messages.isEmpty()) {
                deleteActions.add(action);
            }
        }

        Iterator<TlsAction> iterator = trace.getTlsActions().iterator();
        while (iterator.hasNext()) {
            TlsAction action = iterator.next();
            for (StaticSendingAction toDeleteAction : deleteActions) {
                if (action == toDeleteAction) {
                    iterator.remove();
                    break;
                }
            }
        }
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
            if (messages.isEmpty()) {
                deleteActions.add(action);
            }
        }

        Iterator<TlsAction> iterator = trace.getTlsActions().iterator();
        while (iterator.hasNext()) {
            TlsAction action = iterator.next();
            for (StaticSendingAction toDeleteAction : deleteActions) {
                if (action == toDeleteAction) {
                    iterator.remove();
                    break;
                }
            }
        }
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

        Iterator<TlsAction> iterator = trace.getTlsActions().iterator();
        while (iterator.hasNext()) {
            TlsAction action = iterator.next();
            for (StaticReceivingAction toDeleteAction : deleteActions) {
                if (action == toDeleteAction) {
                    iterator.remove();
                    break;
                }
            }
        }
    }

    public static void replaceReceivingMessage(
            @Nonnull WorkflowTrace trace,
            @Nonnull HandshakeMessageType type,
            @Nullable ProtocolMessage replaceMessage) {
        List<StaticReceivingAction> receivingActions =
                WorkflowTraceConfigurationUtil.getStaticReceivingActionsWithConfiguration(
                        trace, type);
        List<StaticReceivingAction> deleteActions = new ArrayList<>();
        for (StaticReceivingAction action : receivingActions) {

            List<ProtocolMessage> messages = action.getExpectedList(ProtocolMessage.class);
            replaceMessagesInList(messages, type, replaceMessage);
            if (messages.isEmpty()) {
                deleteActions.add(action);
            }
        }
        Iterator<TlsAction> iterator = trace.getTlsActions().iterator();
        while (iterator.hasNext()) {
            TlsAction action = iterator.next();
            for (StaticReceivingAction toDeleteAction : deleteActions) {
                if (action == toDeleteAction) {
                    iterator.remove();
                    break;
                }
            }
        }
    }

    public static void deleteReceivingMessage(WorkflowTrace trace, ProtocolMessageType type)
            throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    public static void deleteReceivingMessage(WorkflowTrace trace, HandshakeMessageType type)
            throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    private static int getTruncationActionIndex(
            WorkflowTrace trace, ProtocolMessageType type, boolean sending, boolean untilLast) {
        for (int i = untilLast ? trace.getTlsActions().size() - 1 : 0;
                untilLast ? i >= 0 : i < trace.getTlsActions().size();
                i += untilLast ? -1 : 1) {
            TlsAction action = trace.getTlsActions().get(i);
            if (action instanceof StaticReceivingAction && !sending) {
                List<ProtocolMessage> messages =
                        ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class);
                for (ProtocolMessage message : messages) {
                    if (message.getProtocolMessageType() == type) {
                        return i;
                    }
                }
            } else if (action instanceof StaticSendingAction && sending) {
                List<ProtocolMessage> messages =
                        ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class);
                for (ProtocolMessage message : messages) {
                    if (message.getProtocolMessageType() == type) {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    private static int getTruncationActionIndex(
            WorkflowTrace trace, HandshakeMessageType type, boolean sending, boolean untilLast) {
        for (int i = untilLast ? trace.getTlsActions().size() - 1 : 0;
                untilLast ? i >= 0 : i < trace.getTlsActions().size();
                i += untilLast ? -1 : 1) {
            TlsAction action = trace.getTlsActions().get(i);
            if (action instanceof StaticReceivingAction && !sending) {
                List<ProtocolMessage> messages =
                        ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class);
                for (ProtocolMessage message : messages) {
                    if (message instanceof HandshakeMessage
                            && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                        return i;
                    }
                }
            } else if (action instanceof StaticSendingAction && sending) {
                List<ProtocolMessage> messages =
                        ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class);
                for (ProtocolMessage message : messages) {
                    if (message instanceof HandshakeMessage
                            && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                        return i;
                    }
                }
            }
        }
        return -1;
    }

    private static void truncate(
            WorkflowTrace trace,
            ProtocolMessageType type,
            WorkflowTruncationMode mode,
            boolean sending,
            boolean untilLast) {
        int truncationIndex = getTruncationActionIndex(trace, type, sending, untilLast);
        if (truncationIndex < 0) {
            LOGGER.warn("Could not truncate WorkflowTrace. Message: {} not found.", type);
            return;
        }

        TlsAction action = trace.getTlsActions().get(truncationIndex);
        List<ProtocolMessage> messages = new ArrayList<>();
        if (action instanceof StaticSendingAction) {
            messages = ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class);
        } else if (action instanceof StaticReceivingAction) {
            messages = ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class);
        }
        int messageIndex = -1;
        for (int i = 0; i < messages.size(); i++) {
            if (messages.get(i).getProtocolMessageType() == type) {
                messageIndex = i;
                if (mode == WorkflowTruncationMode.AFTER) {
                    messageIndex++;
                }

                if (!untilLast) {
                    break;
                }
            }
        }
        if (messageIndex < 0) {
            LOGGER.error(
                    "Could not truncate WorkflowTrace. Message: {} not found. Messages(size): {}",
                    type,
                    messages.size());
            return;
        }
        // Delete all messages after the truncation point
        messages.subList(messageIndex, messages.size()).clear();
        if (messages.isEmpty()) {
            trace.getTlsActions().subList(truncationIndex, trace.getTlsActions().size()).clear();

        } else {
            trace.getTlsActions()
                    .subList(truncationIndex + 1, trace.getTlsActions().size())
                    .clear();
        }
    }

    private static void truncate(
            WorkflowTrace trace,
            HandshakeMessageType type,
            WorkflowTruncationMode mode,
            boolean sending,
            boolean untilLast) {
        int truncationIndex = getTruncationActionIndex(trace, type, sending, untilLast);
        if (truncationIndex < 0) {
            LOGGER.warn("Could not truncate WorkflowTrace. Message: {} not found.", type);
            return;
        }

        TlsAction action = trace.getTlsActions().get(truncationIndex);
        List<ProtocolMessage> messages = new ArrayList<>();
        if (action instanceof StaticSendingAction) {
            messages = ((StaticSendingAction) action).getConfiguredList(ProtocolMessage.class);
        } else if (action instanceof StaticReceivingAction) {
            messages = ((StaticReceivingAction) action).getExpectedList(ProtocolMessage.class);
        }
        int messageIndex = -1;
        for (int i = 0; i < messages.size(); i++) {
            ProtocolMessage message = messages.get(i);
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                messageIndex = i;
                if (mode == WorkflowTruncationMode.AFTER) {
                    messageIndex++;
                }

                if (!untilLast) {
                    break;
                }
            }
        }
        if (messageIndex < 0) {
            LOGGER.error("Could not truncate WorkflowTrace. Message: {} not found.", type);
            return;
        }
        // Delete all messages after the truncation point
        messages.subList(messageIndex, messages.size()).clear();
        if (messages.isEmpty()) {
            trace.getTlsActions().subList(truncationIndex, trace.getTlsActions().size()).clear();

        } else {
            trace.getTlsActions()
                    .subList(truncationIndex + 1, trace.getTlsActions().size())
                    .clear();
        }
    }

    public static void truncateAt(
            WorkflowTrace trace, HandshakeMessageType type, boolean sending, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateAt(
            WorkflowTrace trace, ProtocolMessageType type, boolean sending, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateSendingAt(
            WorkflowTrace trace, HandshakeMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateSendingAt(
            WorkflowTrace trace, ProtocolMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateReceivingAt(
            WorkflowTrace trace, HandshakeMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateReceivingAt(
            WorkflowTrace trace, ProtocolMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateSendingAfter(
            WorkflowTrace trace, HandshakeMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateSendingAfter(
            WorkflowTrace trace, ProtocolMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateReceivingAfter(
            WorkflowTrace trace, HandshakeMessageType type, boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, false, untilLast);
    }

    public static void truncateReceivingAfter(
            WorkflowTrace trace, ProtocolMessageType type, boolean untilLast) {
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
