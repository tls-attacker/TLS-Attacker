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

public class WorkflowTraceResultUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    public static ProtocolMessage getFirstReceivedMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstReceivedMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static SSL2Message getFirstReceivedMessage(WorkflowTrace trace, SSL2MessageType type) {
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
            WorkflowTrace trace, HandshakeMessageType type) {
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
            WorkflowTrace trace, ProtocolMessageType type) {
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

    public static ProtocolMessage getFirstSentMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllSentMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstSentMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllSentMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static ExtensionMessage getFirstSentExtension(WorkflowTrace trace, ExtensionType type) {
        List<ExtensionMessage> extensionList = getAllSentExtensions(trace);
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

    public static List<HandshakeMessage> getAllSentHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllSentMessages(trace));
    }

    public static List<HandshakeMessage> getAllReceivedHandshakeMessages(WorkflowTrace trace) {
        return filterHandshakeMessagesFromList(getAllReceivedMessages(trace));
    }

    public static List<ExtensionMessage> getAllSentExtensions(WorkflowTrace trace) {
        List<HandshakeMessage> handshakeMessageList = getAllSentHandshakeMessages(trace);
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

    public static HandshakeMessage getLastSentMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllSentMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastSentMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllSentMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static boolean didReceiveMessage(WorkflowTrace trace, ProtocolMessageType type) {
        return WorkflowTraceResultUtil.getFirstReceivedMessage(trace, type) != null;
    }

    public static boolean didReceiveMessage(WorkflowTrace trace, HandshakeMessageType type) {
        return WorkflowTraceResultUtil.getFirstReceivedMessage(trace, type) != null;
    }

    public static boolean didReceiveMessage(WorkflowTrace trace, SSL2MessageType type) {
        return getFirstReceivedMessage(trace, type) != null;
    }

    public static boolean didSendMessage(WorkflowTrace trace, ProtocolMessageType type) {
        return getFirstSentMessage(trace, type) != null;
    }

    public static boolean didSendMessage(WorkflowTrace trace, HandshakeMessageType type) {
        return getFirstSentMessage(trace, type) != null;
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

    private static List<HandshakeMessage> filterHandshakeMessagesFromList(
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

    public static List<ProtocolMessage> getAllReceivedMessagesOfType(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            if (message.getProtocolMessageType() == type) {
                receivedMessage.add(message);
            }
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllSentMessages(WorkflowTrace trace) {
        List<ProtocolMessage> sendMessages = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            sendMessages.addAll(action.getSentMessages());
        }
        return sendMessages;
    }

    public static Boolean didReceiveTypeBeforeType(
            WorkflowTrace trace,
            ProtocolMessageType protocolMessageType,
            HandshakeMessageType type) {
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

    public static List<Record> getAllSentRecords(WorkflowTrace trace) {
        List<Record> sendRecords = new LinkedList<>();
        for (SendingAction action : trace.getSendingActions()) {
            if (action.getSentRecords() != null) {
                sendRecords.addAll(action.getSentRecords());
            }
        }
        return sendRecords;
    }

    public static List<ReceivingAction> getActionsThatReceived(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();
        List<ReceivingAction> resultActions = new LinkedList<>();
        for (ReceivingAction action : receivingActions) {
            if (action.getReceivedMessages() != null) {
                for (ProtocolMessage message : action.getReceivedMessages()) {
                    if (message.getProtocolMessageType() == type) {
                        resultActions.add(action);
                        break;
                    }
                }
            }
        }
        return resultActions;
    }

    public static List<SendingAction> getActionsThatSent(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<SendingAction> sendingAction = trace.getSendingActions();
        List<SendingAction> resultActions = new LinkedList<>();
        for (SendingAction action : sendingAction) {
            if (action.getSentMessages() != null) {
                for (ProtocolMessage message : action.getSentMessages()) {
                    if (message instanceof HandshakeMessage) {
                        HandshakeMessage handshakeMessage = (HandshakeMessage) message;
                        if (handshakeMessage.getHandshakeMessageType() == type) {
                            resultActions.add(action);
                            break;
                        }
                    }
                }
            }
        }
        return resultActions;
    }

    public static List<SendingAction> getActionsThatSent(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<SendingAction> sendingAction = trace.getSendingActions();
        List<SendingAction> resultActions = new LinkedList<>();
        for (SendingAction action : sendingAction) {
            if (action.getSentMessages() != null) {
                for (ProtocolMessage message : action.getSentMessages()) {
                    if (message.getProtocolMessageType() == type) {
                        resultActions.add(action);
                        break;
                    }
                }
            }
        }
        return resultActions;
    }

    public static List<ReceivingAction> getActionsThatReceived(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ReceivingAction> receivingActions = trace.getReceivingActions();
        List<ReceivingAction> resultActions = new LinkedList<>();
        for (ReceivingAction action : receivingActions) {
            if (action.getReceivedMessages() != null) {
                for (ProtocolMessage message : action.getReceivedMessages()) {
                    if (message instanceof HandshakeMessage) {
                        HandshakeMessage handshakeMessage = (HandshakeMessage) message;
                        if (handshakeMessage.getHandshakeMessageType() == type) {
                            resultActions.add(action);
                            break;
                        }
                    }
                }
            }
        }
        return resultActions;
    }

    public static TlsAction getAllActionWithResult(WorkflowTrace trace, HandshakeMessageType type) {
        TlsAction receiving = getFirstActionThatReceived(trace, type);
        TlsAction sending = getFirstActionThatSent(trace, type);
        return getEarlierAction(trace, receiving, sending);
    }

    public static TlsAction getFirstActionWithResult(
            WorkflowTrace trace, ProtocolMessageType type) {
        TlsAction receiving = getFirstActionThatReceived(trace, type);
        TlsAction sending = getFirstActionThatSent(trace, type);
        return getEarlierAction(trace, receiving, sending);
    }

    public static TlsAction getFirstActionThatSent(WorkflowTrace trace, ProtocolMessageType type) {
        if (!getActionsThatSent(trace, type).isEmpty()) {
            return (TlsAction) getActionsThatSent(trace, type).get(0);
        }
        return null;
    }

    public static TlsAction getFirstActionThatSent(WorkflowTrace trace, HandshakeMessageType type) {
        if (!getActionsThatSent(trace, type).isEmpty()) {
            return (TlsAction) getActionsThatSent(trace, type).get(0);
        }
        return null;
    }

    public static TlsAction getFirstActionThatReceived(
            WorkflowTrace trace, ProtocolMessageType type) {
        if (!getActionsThatReceived(trace, type).isEmpty()) {
            return (TlsAction) getActionsThatReceived(trace, type).get(0);
        }
        return null;
    }

    public static TlsAction getFirstActionThatReceived(
            WorkflowTrace trace, HandshakeMessageType type) {
        if (!getActionsThatReceived(trace, type).isEmpty()) {
            return (TlsAction) getActionsThatReceived(trace, type).get(0);
        }
        return null;
    }

    public static TlsAction getLastActionWithResult(
            WorkflowTrace trace, HandshakeMessageType type) {
        ReceivingAction receiving = getLastReceivingActionForMessage(trace, type);
        SendingAction sending = getLastActionThatSent(trace, type);

        return getLaterAction(trace, (TlsAction) receiving, (TlsAction) sending);
    }

    public static TlsAction getLastActionWithResult(WorkflowTrace trace, ProtocolMessageType type) {
        ReceivingAction receiving = getLastReceivingActionForMessage(trace, type);
        SendingAction sending = getLastActionThatSent(trace, type);

        return getLaterAction(trace, (TlsAction) receiving, (TlsAction) sending);
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

    public static SendingAction getLastActionThatSent(
            WorkflowTrace trace, ProtocolMessageType type) {
        if (!getActionsThatSent(trace, type).isEmpty()) {
            List<SendingAction> sendActions = getActionsThatSent(trace, type);
            return sendActions.get(sendActions.size() - 1);
        }
        return null;
    }

    public static SendingAction getLastActionThatSent(
            WorkflowTrace trace, HandshakeMessageType type) {
        if (!getActionsThatSent(trace, type).isEmpty()) {
            List<SendingAction> sendActions = getActionsThatSent(trace, type);
            return sendActions.get(sendActions.size() - 1);
        }
        return null;
    }

    public static ReceivingAction getLastReceivingActionForMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        if (!getActionsThatReceived(trace, type).isEmpty()) {
            List<ReceivingAction> receiveActions = getActionsThatReceived(trace, type);
            return receiveActions.get(receiveActions.size() - 1);
        }
        return null;
    }

    public static ReceivingAction getLastReceivingActionForMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        if (!getActionsThatReceived(trace, type).isEmpty()) {
            List<ReceivingAction> rcvActions = getActionsThatReceived(trace, type);
            return rcvActions.get(rcvActions.size() - 1);
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

    private WorkflowTraceResultUtil() {}
}
