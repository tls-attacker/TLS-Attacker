/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.socket.AliasedConnection;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class WorkflowTraceUtil {

    protected static final Logger LOGGER = LogManager.getLogger(WorkflowTraceUtil.class);

    public static void mixInDefaultsForExecution(WorkflowTrace trace, Config config) {
        mixInDefaultsForExecution(trace, config, config.getDefaulRunningMode());
    }

    /**
     * Merge in default values from Config if necessary.
     */
    public static void mixInDefaultsForExecution(WorkflowTrace trace, Config config, RunningModeType mode) {
        List<AliasedConnection> traceConnections = trace.getConnections();
        AliasedConnection defaultInCon = config.getDefaultServerConnection();
        AliasedConnection defaultOutCon = config.getDefaultClientConnection();

        if (traceConnections == null) {
            traceConnections = new ArrayList<>();
            trace.setConnections(traceConnections);
        }

        if (traceConnections.isEmpty()) {
            if (null == mode) {
                LOGGER.debug("No running mode defined, assuming mode is CLIENT");
                mode = RunningModeType.CLIENT;
            }
            switch (mode) {
                case CLIENT:
                    traceConnections.add(defaultOutCon);
                    break;
                case SERVER:
                    traceConnections.add(defaultInCon);
                    break;
                default:
                    throw new ConfigurationException("No connections defined in workflow trace and"
                            + "default configuration for this running mode (" + mode + ") is not "
                            + "supported. Please define some connections in the workflow trace.\n");
            }
        }

        for (AliasedConnection traceCon : traceConnections) {
            ConnectionEndType localConEndType = traceCon.getLocalConnectionEndType();
            if (null == localConEndType) {
                throw new ConfigurationException("WorkflowTrace defines a connection with an"
                        + "empty localConnectionEndType. Don't know how to handle this!");
            } else
                switch (traceCon.getLocalConnectionEndType()) {
                    case CLIENT:
                        traceCon.mixInDefaults(defaultOutCon);
                        break;
                    case SERVER:
                        traceCon.mixInDefaults(defaultInCon);
                        break;
                    default:
                        throw new ConfigurationException("WorkflowTrace defines a connection with an"
                                + "unknown localConnectionEndType (" + localConEndType + "). Don't know "
                                + "how to handle this!");
                }
        }
    }

    public static void stripDefaultsForSerialization(WorkflowTrace trace, Config config) {
        stripDefaultsForSerialization(trace, config, config.getDefaulRunningMode());
    }

    /**
     * Reverse mergeInDefaultsForExecution(). Results in a WorkflowTrace ready
     * for serialization with JAXB.
     */
    public static void stripDefaultsForSerialization(WorkflowTrace trace, Config config, RunningModeType mode) {
        List<AliasedConnection> traceConnections = trace.getConnections();
        AliasedConnection defaultInCon = config.getDefaultServerConnection();
        AliasedConnection defaultOutCon = config.getDefaultClientConnection();

        for (AliasedConnection traceCon : traceConnections) {
            ConnectionEndType localConEndType = traceCon.getLocalConnectionEndType();
            if (null == localConEndType) {
                throw new ConfigurationException("WorkflowTrace defines a connection with an"
                        + "empty localConnectionEndType. Don't know how to handle this!");
            } else
                switch (traceCon.getLocalConnectionEndType()) {
                    case CLIENT:
                        traceCon.stripDefaults(defaultOutCon);
                        break;
                    case SERVER:
                        traceCon.stripDefaults(defaultInCon);
                        break;
                    default:
                        throw new ConfigurationException("WorkflowTrace defines a connection with an"
                                + "unknown localConnectionEndType (" + localConEndType + "). Don't know "
                                + "how to handle this!");
                }

        }
    }

    public static ProtocolMessage getFirstReceivedMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static HandshakeMessage getLastReceivedMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastReceivedMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static ProtocolMessage getFirstSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(0);
        }
    }

    public static HandshakeMessage getFirstSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(0);
        }
    }

    public static HandshakeMessage getLastSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        List<HandshakeMessage> handshakeMessageList = filterHandshakeMessagesFromList(messageList);
        handshakeMessageList = filterMessageList(handshakeMessageList, type);
        if (handshakeMessageList.isEmpty()) {
            return null;
        } else {
            return handshakeMessageList.get(handshakeMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllSendMessages(trace);
        messageList = filterMessageList(messageList, type);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    public static boolean didReceiveMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didReceiveMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstReceivedMessage(type, trace) != null;
    }

    public static boolean didSendMessage(ProtocolMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static boolean didSendMessage(HandshakeMessageType type, WorkflowTrace trace) {
        return getFirstSendMessage(type, trace) != null;
    }

    public static ProtocolMessage getLastReceivedMessage(WorkflowTrace trace) {
        List<ProtocolMessage> messageList = getAllReceivedMessages(trace);
        if (messageList.isEmpty()) {
            return null;
        } else {
            return messageList.get(messageList.size() - 1);
        }
    }

    private static List<ProtocolMessage> filterMessageList(List<ProtocolMessage> messages, ProtocolMessageType type) {
        List<ProtocolMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.getProtocolMessageType() == type) {
                returnedMessages.add(protocolMessage);
            }
        }
        return returnedMessages;
    }

    private static List<HandshakeMessage> filterHandshakeMessagesFromList(List<ProtocolMessage> messages) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.isHandshakeMessage()) {
                returnedMessages.add((HandshakeMessage) protocolMessage);
            }
        }
        return returnedMessages;
    }

    private static List<HandshakeMessage> filterMessageList(List<HandshakeMessage> messages, HandshakeMessageType type) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (HandshakeMessage handshakeMessage : messages) {
            if (handshakeMessage.getHandshakeMessageType() == type) {
                returnedMessages.add(handshakeMessage);
            }
        }
        return returnedMessages;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace) {
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ReceivingAction action : trace.getReceivingActions()) {
            receivedMessage.addAll(action.getReceivedMessages());
        }
        return receivedMessage;
    }

    public static List<ProtocolMessage> getAllReceivedMessages(WorkflowTrace trace, ProtocolMessageType type) {
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

    public static Boolean didReceiveTypeBeforeType(ProtocolMessageType protocolMessageType, HandshakeMessageType type,
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
}
