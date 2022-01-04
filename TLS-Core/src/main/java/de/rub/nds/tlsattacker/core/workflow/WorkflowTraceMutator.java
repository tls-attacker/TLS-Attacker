/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.TlsMessage;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;

public class WorkflowTraceMutator {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void replaceMessagesInList(@Nonnull List<ProtocolMessage> messageList,
        @Nonnull ProtocolMessageType type, @Nullable ProtocolMessage replaceMessage) {
        if (replaceMessage != null) {
            messageList.replaceAll(e -> {
                if (e instanceof TlsMessage && ((TlsMessage) e).getProtocolMessageType() == type) {
                    return replaceMessage;
                }
                return e;
            });
        } else {
            messageList.removeIf(m -> {
                if (m instanceof TlsMessage && ((TlsMessage) m).getProtocolMessageType() == type) {
                    return true;
                }
                return false;
            });
        }
    }

    private static void replaceMessagesInList(@Nonnull List<ProtocolMessage> messageList,
        @Nonnull HandshakeMessageType type, @Nullable ProtocolMessage replaceMessage) {
        if (replaceMessage != null) {
            messageList.replaceAll(e -> {
                if (e instanceof HandshakeMessage && ((HandshakeMessage) e).getHandshakeMessageType() == type) {
                    return replaceMessage;
                }
                return e;
            });
        } else {
            messageList.removeIf(m -> {
                if (m instanceof HandshakeMessage && ((HandshakeMessage) m).getHandshakeMessageType() == type) {
                    return true;
                }
                return false;
            });
        }
    }

    public static void replaceSendingMessage(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        @Nullable ProtocolMessage replaceMessage) {
        List<SendingAction> sendingActions = WorkflowTraceUtil.getSendingActionsForMessage(type, trace);
        List<SendingAction> deleteActions = new ArrayList<>();
        for (SendingAction i : sendingActions) {
            List<ProtocolMessage> messages = i.getSendMessages();
            replaceMessagesInList(messages, type, replaceMessage);
            if (messages.size() == 0) {
                deleteActions.add(i);
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void replaceSendingMessage(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        @Nullable HandshakeMessage replaceMessage) {
        List<SendingAction> sendingActions = WorkflowTraceUtil.getSendingActionsForMessage(type, trace);
        List<SendingAction> deleteActions = new ArrayList<>();
        for (SendingAction i : sendingActions) {
            List<ProtocolMessage> messages = i.getSendMessages();
            replaceMessagesInList(messages, type, replaceMessage);
            if (messages.size() == 0) {
                deleteActions.add(i);
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void deleteSendingMessage(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type) {
        replaceSendingMessage(trace, type, null);
    }

    public static void deleteSendingMessage(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type) {
        replaceSendingMessage(trace, type, null);
    }

    public static void replaceReceivingMessage(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        @Nullable TlsMessage replaceMessage) throws WorkflowTraceMutationException {
        List<ReceivingAction> receivingActions = WorkflowTraceUtil.getReceivingActionsForMessage(type, trace);
        List<ReceivingAction> deleteActions = new ArrayList<>();
        for (ReceivingAction i : receivingActions) {
            if (i instanceof ReceiveAction) {
                List<ProtocolMessage> messages = ((ReceiveAction) i).getExpectedMessages();
                replaceMessagesInList(messages, type, replaceMessage);
                if (messages.size() == 0) {
                    deleteActions.add(i);
                }
            } else if (i instanceof ReceiveTillAction) {
                TlsMessage message = ((ReceiveTillAction) i).getWaitTillMessage();
                if (message.getProtocolMessageType() == type) {
                    if (replaceMessage == null) {
                        throw new WorkflowTraceMutationException(
                            "ReceiveTillAction cannot be deleted, because this will probably break your workflow.");
                    }
                    ((ReceiveTillAction) i).setWaitTillMessage(replaceMessage);
                }
            } else {
                throw new WorkflowTraceMutationException("Unsupported ReceivingAction, could not mutate workflow.");
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void replaceReceivingMessage(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        @Nullable TlsMessage replaceMessage) throws WorkflowTraceMutationException {
        List<ReceivingAction> receivingActions = WorkflowTraceUtil.getReceivingActionsForMessage(type, trace);
        List<ReceivingAction> deleteActions = new ArrayList<>();
        for (ReceivingAction i : receivingActions) {
            if (i instanceof ReceiveAction) {
                List<ProtocolMessage> messages = ((ReceiveAction) i).getExpectedMessages();
                replaceMessagesInList(messages, type, replaceMessage);
                if (messages.size() == 0) {
                    deleteActions.add(i);
                }
            } else if (i instanceof ReceiveTillAction) {
                TlsMessage message = ((ReceiveTillAction) i).getWaitTillMessage();
                if (message.isHandshakeMessage() && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    if (replaceMessage == null) {
                        throw new WorkflowTraceMutationException(
                            "ReceiveTillAction cannot be deleted, because this will probably break your workflow.");
                    }
                    ((ReceiveTillAction) i).setWaitTillMessage(replaceMessage);
                }
            } else {
                throw new WorkflowTraceMutationException("Unsupported ReceivingAction, could not mutate workflow.");
            }
        }

        trace.getTlsActions().removeAll(deleteActions);
    }

    public static void deleteReceivingMessage(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type)
        throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    public static void deleteReceivingMessage(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type)
        throws WorkflowTraceMutationException {
        replaceReceivingMessage(trace, type, null);
    }

    private static void truncate(@Nonnull WorkflowTrace trace, @Nonnull Object type, WorkflowTruncationMode mode,
        Boolean sending, Boolean untilLast) {
        TlsAction action = null;
        if (untilLast != null && untilLast == true) {
            if (type instanceof HandshakeMessageType) {
                if (sending == null) {
                    action = WorkflowTraceUtil.getLastActionForMessage((HandshakeMessageType) type, trace);
                } else if (sending) {
                    action = WorkflowTraceUtil.getLastSendingActionForMessage((HandshakeMessageType) type, trace);
                } else {
                    action = WorkflowTraceUtil.getLastReceivingActionForMessage((HandshakeMessageType) type, trace);
                }
            } else if (type instanceof ProtocolMessageType) {
                if (sending == null) {
                    action = WorkflowTraceUtil.getLastActionForMessage((ProtocolMessageType) type, trace);
                } else if (sending) {
                    action = WorkflowTraceUtil.getLastSendingActionForMessage((ProtocolMessageType) type, trace);
                } else {
                    action = WorkflowTraceUtil.getLastReceivingActionForMessage((ProtocolMessageType) type, trace);
                }
            }
        } else {
            if (type instanceof HandshakeMessageType) {
                if (sending == null) {
                    action = WorkflowTraceUtil.getFirstActionForMessage((HandshakeMessageType) type, trace);
                } else if (sending) {
                    action = WorkflowTraceUtil.getFirstSendingActionForMessage((HandshakeMessageType) type, trace);
                } else {
                    action = WorkflowTraceUtil.getFirstReceivingActionForMessage((HandshakeMessageType) type, trace);
                }
            } else if (type instanceof ProtocolMessageType) {
                if (sending == null) {
                    action = WorkflowTraceUtil.getFirstActionForMessage((ProtocolMessageType) type, trace);
                } else if (sending) {
                    action = WorkflowTraceUtil.getFirstSendingActionForMessage((ProtocolMessageType) type, trace);
                } else {
                    action = WorkflowTraceUtil.getFirstReceivingActionForMessage((ProtocolMessageType) type, trace);
                }
            }
        }
        if (action == null) {
            return;
        }

        int messageIndex = -1;
        int actionIndex = trace.getTlsActions().indexOf(action);
        List<ProtocolMessage> messages = new ArrayList<>();
        if (action instanceof SendingAction) {
            if (action instanceof SendAction) {
                messages = ((SendAction) action).getSendMessages();
            } else if (!(action instanceof SendDynamicServerCertificateAction)
                && !(action instanceof SendDynamicClientKeyExchangeAction)
                && !(action instanceof SendDynamicServerKeyExchangeAction)) {
                LOGGER.warn(
                    "Unsupported action for truncating operation, actions after the selected action are still being deleted.");
            }
        } else if (action instanceof ReceivingAction) {
            if (action instanceof ReceiveAction) {
                messages = ((ReceiveAction) action).getExpectedMessages();
            } else if (!(action instanceof ReceiveTillAction)) {
                LOGGER.warn(
                    "Unsupported action for truncating operation, actions after the selected action are still being deleted.");
            }
        }

        for (ProtocolMessage i : messages) {
            if (type instanceof HandshakeMessageType) {
                if (!(i instanceof HandshakeMessage)) {
                    continue;
                }
                if (((HandshakeMessage) i).getHandshakeMessageType() == type) {
                    messageIndex = messages.indexOf(i);
                    if (messageIndex == 0 && mode == WorkflowTruncationMode.AT) {
                        actionIndex -= 1;
                    }
                    break;
                }
            } else {
                if (i instanceof TlsMessage && ((TlsMessage) i).getProtocolMessageType() == type) {
                    messageIndex = messages.indexOf(i);
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

    public static void truncateAt(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, null, untilLast);
    }

    public static void truncateAt(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type, Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, null, untilLast);
    }

    public static void truncateAt(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type, Boolean sending,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateAt(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type, Boolean sending,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, sending, untilLast);
    }

    public static void truncateSendingAt(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateSendingAt(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, true, untilLast);
    }

    public static void truncateReceivingAt(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateReceivingAt(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AT, false, untilLast);
    }

    public static void truncateAfter(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, null, untilLast);
    }

    public static void truncateAfter(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, null, untilLast);
    }

    public static void truncateSendingAfter(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateSendingAfter(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, true, untilLast);
    }

    public static void truncateReceivingAfter(@Nonnull WorkflowTrace trace, @Nonnull HandshakeMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, false, untilLast);
    }

    public static void truncateReceivingAfter(@Nonnull WorkflowTrace trace, @Nonnull ProtocolMessageType type,
        Boolean untilLast) {
        truncate(trace, type, WorkflowTruncationMode.AFTER, false, untilLast);
    }

}
