/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class WorkflowTraceUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ProtocolMessage getFirstReceivedMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstReceivedMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static SSL2Message getFirstReceivedMessage(SSL2MessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<SSL2Message> ssl2MessageList =
                messageList.stream()
                        .filter(SSL2Message.class::isInstance)
                        .map(protocolMessage -> (SSL2Message) protocolMessage)
                        .collect(Collectors.toList());
        ssl2MessageList = filterMessageList(ssl2MessageList, type);
        if (ssl2MessageList.isEmpty()) {
            return null;
        } else {
            return ssl2MessageList.get(0);
        }
    }

    public static HandshakeMessage getLastReceivedMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastReceivedMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastReceivedMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static Record getLastReceivedRecord(WorkflowTrace trace) {
        List<Record> recordList = getAllReceivedRecords(trace);
        if (recordList.isEmpty()) {
            return null;
        } else {
            return recordList.get(recordList.size() - 1);
        }
    }

    public static ProtocolMessage getFirstSendMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstSendMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static ExtensionMessage getFirstSendExtension(ExtensionType type, WorkflowTrace trace) {
        List<ExtensionMessage> extensionList = getAllSendExtensions(trace);
        extensionList = filterExtensionList(extensionList, type);
        if (extensionList.isEmpty()) {
            return null;
        } else {
            return extensionList.get(0);
        }
    }

    public static TlsAction getFirstFailedAction(WorkflowTrace trace) {
        for (TlsAction action : trace.getTlsActions()) {
            if (!action.executedAsPlanned()) {
                return action;
            }
        }
        return null;
    }

    public static List<HandshakeMessage> getAllSendHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllSendMessages(trace));
    }

    public static List<HandshakeMessage> getAllReceivedHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllReceivedMessages(trace));
    }

    public static List<ExtensionMessage> getAllSendExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllSendHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static List<ExtensionMessage> getAllReceivedExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllReceivedHandshakeMessages(trace);
        List<ExtensionMessage> extensionList = new LinkedList<>();
        for (HandshakeMessage message : handshakeMessageList) {
            extensionList.addAll(message.getExtensions());
        }
        return extensionList;
    }

    public static HandshakeMessage getLastSendMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastSendMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static boolean didReceiveMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return WorkflowTraceUtil.getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didReceiveMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return WorkflowTraceUtil.getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didReceiveMessage(SSL2MessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static boolean didSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    private static List<ProtocolMessage> filterMessageList(
            List<ProtocolMessage> messages, ProtocolMessageType type) {
        List<ProtocolMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.getProtocolMessageType() == type) {
                returnedMessages.add(protocolMessage);
            }
        }
        return returnedMessages;
    }

    private static List<HandshakeMessage> filterMessageList(
            List<HandshakeMessage> messages, HandshakeMessageType type) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (HandshakeMessage handshakeMessage : messages) {
            if (handshakeMessage.getHandshakeMessageType() == type) {
                returnedMessages.add(handshakeMessage);
            }
        }
        return returnedMessages;
    }

    private static List<SSL2Message> filterMessageList(
            List<SSL2Message> messages, SSL2MessageType type) {
        List<SSL2Message> returnedMessages = new LinkedList<>();
        for (SSL2Message ssl2Message : messages) {
            if (ssl2Message.getSsl2MessageType() == type) {
                returnedMessages.add(ssl2Message);
            }
        }
        return returnedMessages;
    }

    private static List<ExtensionMessage> filterExtensionList(
            List<ExtensionMessage> extensions, ExtensionType type) {
        List<ExtensionMessage> resultList = new LinkedList<>();
        for (ExtensionMessage extension : extensions) {
            if (extension.getExtensionTypeConstant() == type) {
                resultList.add(extension);
            }
        }
        return resultList;
    }

    public static List<HandshakeMessage> filterHandshakeMessagesFromList(
            List<ProtocolMessage> messages) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage instanceof HandshakeMessage) {
                returnedMessages.add((HandshakeMessage) protocolMessage);
            }
        }
        return returnedMessages;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedMessages() != null) {
                receivedMessage.addAll(action.getReceivedMessages());
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            if (message.getProtocolMessageType() == type) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSendMessages());
        }
        return sendMessages;
    }

    public static Boolean didReceiveTypeBeforeType(
            ProtocolMessageType protocolMessageType,
            HandshakeMessageType type,
            WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessages = getAllReceivedMessages(trace);
        for (ProtocolMessage message : receivedMessages) {
            if (message.getProtocolMessageType() == protocolMessageType) {
                return true;
            }
            if (message instanceof HandshakeMessage) {
                if (((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    return false;
                }
            }
        }
        return false;
    }

    public static List<Record> getAllReceivedRecords(WorkflowTrace trace) {
        List<Record> receivedRecords = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            if (action.getReceivedRecords() != null) {
                receivedRecords.addAll(action.getReceivedRecords());
            }
        }
        return receivedRecords;
    }

    public static List<Record> getAllSendRecords(WorkflowTrace trace) {
        List<Record> sendRecords = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            if (action.getSendRecords() != null) {
                sendRecords.addAll(action.getSendRecords());
            }
        }
        return sendRecords;
    }

    public static SendingAction getLastSendingAction(WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        return sendingActions.get(sendingActions.size() - 1);
    }

    public static List<SendingAction> getSendingActionsForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();
        sendingActions.removeIf(
                (SendingAction i) -> {
                    List<ProtocolMessageType> types = i.getGoingToSendProtocolMessageTypes();
                    return !types.contains(type);
                });
        return sendingActions;
    }

    public static List<SendingAction> getSendingActionsForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<SendingAction> sendingActions = trace.getSendingActions();

        sendingActions.removeIf(
                (SendingAction i) -> {
                    List<HandshakeMessageType> handshakeTypes =
                            i.getGoingToSendHandshakeMessageTypes();
                    return !handshakeTypes.contains(type);
                });
        return sendingActions;
    }

    public static List<ReceivingAction> getReceivingActionsForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();

        receivingActions.removeIf(
                (ReceivingAction i) -> {
                    List<ProtocolMessageType> types = i.getGoingToReceiveProtocolMessageTypes();
                    return !types.contains(type);
                });

        return receivingActions;
    }

    public static List<ReceivingAction> getReceivingActionsForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();

        receivingActions.removeIf(
                (ReceivingAction i) -> {
                    List<HandshakeMessageType> types = i.getGoingToReceiveHandshakeMessageTypes();
                    return !types.contains(type);
                });

        return receivingActions;
    }

    public static TlsAction getFirstActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        TlsAction receiving = getFirstReceivingActionForMessage(type, trace);
        TlsAction sending = getFirstSendingActionForMessage(type, trace);
        return getEarlierAction(trace, receiving, sending);
    }

    public static TlsAction getFirstActionForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        TlsAction receiving = getFirstReceivingActionForMessage(type, trace);
        TlsAction sending = getFirstSendingActionForMessage(type, trace);
        return getEarlierAction(trace, receiving, sending);
    }

    public static TlsAction getFirstSendingActionForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getSendingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstSendingActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getSendingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstReceivingActionForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getReceivingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getFirstReceivingActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            return (TlsAction) getReceivingActionsForMessage(type, trace).get(0);
        }
        return null;
    }

    public static TlsAction getLastActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        TlsAction receiving = getLastReceivingActionForMessage(type, trace);
        TlsAction sending = getLastSendingActionForMessage(type, trace);

        return getLaterAction(trace, receiving, sending);
    }

    public static TlsAction getLastActionForMessage(ProtocolMessageType type, WorkflowTrace trace) {
        TlsAction receiving = getLastReceivingActionForMessage(type, trace);
        TlsAction sending = getLastSendingActionForMessage(type, trace);

        return getLaterAction(trace, receiving, sending);
    }

    public static TlsAction getLaterAction(
            WorkflowTrace trace, TlsAction action1, TlsAction action2) {
        if ((action1 == null && action2 == null)
                || (!containsIdenticalAction(trace, action1)
                        && !containsIdenticalAction(trace, action2))) {
            return null;
        } else if (action1 == null || !containsIdenticalAction(trace, action1)) {
            return action2;
        } else if (action2 == null || !containsIdenticalAction(trace, action2)) {
            return action1;
        }

        return indexOfIdenticalAction(trace, action1) > indexOfIdenticalAction(trace, action2)
                ? action1
                : action2;
    }

    public static TlsAction getEarlierAction(
            WorkflowTrace trace, TlsAction action1, TlsAction action2) {
        if ((action1 == null && action2 == null)
                || (!containsIdenticalAction(trace, action1)
                        && !containsIdenticalAction(trace, action2))) {
            return null;
        } else if (action1 == null || !containsIdenticalAction(trace, action1)) {
            return action2;
        } else if (action2 == null || !containsIdenticalAction(trace, action2)) {
            return action1;
        }

        return indexOfIdenticalAction(trace, action1) < indexOfIdenticalAction(trace, action2)
                ? action1
                : action2;
    }

    public static TlsAction getLastSendingActionForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            List<SendingAction> sndActions = getSendingActionsForMessage(type, trace);
            return (TlsAction) sndActions.get(sndActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastSendingActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        if (!getSendingActionsForMessage(type, trace).isEmpty()) {
            List<SendingAction> sndActions = getSendingActionsForMessage(type, trace);
            return (TlsAction) sndActions.get(sndActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastReceivingActionForMessage(
            ProtocolMessageType type, WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            List<ReceivingAction> rcvActions = getReceivingActionsForMessage(type, trace);
            return (TlsAction) rcvActions.get(rcvActions.size() - 1);
        }
        return null;
    }

    public static TlsAction getLastReceivingActionForMessage(
            HandshakeMessageType type, WorkflowTrace trace) {
        if (!getReceivingActionsForMessage(type, trace).isEmpty()) {
            List<ReceivingAction> rcvActions = getReceivingActionsForMessage(type, trace);
            return (TlsAction) rcvActions.get(rcvActions.size() - 1);
        }
        return null;
    }

    /**
     * Returns all Messages of the WorkflowTrace that contain unread bytes. They can be accessed
     * over the {@link de.rub.nds.tlsattacker.core.layer.LayerProcessingResult}
     */
    public static List<MessageAction> getMessageActionsWithUnreadBytes(
            @Nonnull WorkflowTrace trace) {
        List<MessageAction> messageActionsWithUnreadBytes = new LinkedList<>();
        for (TlsAction action : trace.getTlsActions()) {
            if (action instanceof MessageAction
                    && action instanceof ReceivingAction
                    && ((MessageAction) action).getLayerStackProcessingResult() != null
                    && ((MessageAction) action).getLayerStackProcessingResult().hasUnreadBytes()) {
                messageActionsWithUnreadBytes.add((MessageAction) action);
            }
        }
        return messageActionsWithUnreadBytes;
    }

    public static boolean hasUnreadBytes(@Nonnull WorkflowTrace trace) {
        return !(getMessageActionsWithUnreadBytes(trace).isEmpty());
    }

    public static int indexOfIdenticalAction(WorkflowTrace trace, TlsAction action) {
        if (trace.getTlsActions() != null) {
            for (int i = 0; i < trace.getTlsActions().size(); i++) {
                if (trace.getTlsActions().get(i) == action) {
                    return i;
                }
            }
        }
        return -1;
    }

    public static boolean containsIdenticalAction(WorkflowTrace trace, TlsAction action) {
        if (trace.getTlsActions() != null) {
            return trace.getTlsActions().stream().anyMatch(listed -> listed == action);
        }
        return false;
    }

    private WorkflowTraceUtil() {}
}
