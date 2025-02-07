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
import de.rub.nds.tlsattacker.core.layer.data.DataContainer;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.workflow.action.StaticReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.action.StaticSendingAction;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class WorkflowTraceConfigurationUtil {

    private WorkflowTraceConfigurationUtil() {}

    public static ProtocolMessage getFirstStaticConfiguredSendMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredSendMessages(trace);
        for (ProtocolMessage message : messageList) {
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                return message;
            }
        }
        return null;
    }

    public static ProtocolMessage getFirstStaticConfiguredReceiveMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredReceiveMessages(trace);
        for (ProtocolMessage message : messageList) {
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                return message;
            }
        }
        return null;
    }

    public static ProtocolMessage getFirstStaticConfiguredSendMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredSendMessages(trace);
        for (ProtocolMessage message : messageList) {
            if (message.getProtocolMessageType() == type) {
                return message;
            }
        }
        return null;
    }

    public static StaticReceivingAction getFirstStaticConfiguredReceiveAction(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticReceivingAction> actionList = trace.getStaticConfiguredReceivingActions();
        for (StaticReceivingAction action : actionList) {
            for (ProtocolMessage message : action.getExpectedList(ProtocolMessage.class)) {
                if (message.getProtocolMessageType() == type) {
                    return action;
                }
            }
        }
        return null;
    }

    public static StaticSendingAction getFirstStaticConfiguredSendAction(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticSendingAction> actionList = trace.getStaticConfiguredSendingActions();
        for (StaticSendingAction action : actionList) {
            for (ProtocolMessage message : action.getConfiguredList(ProtocolMessage.class)) {
                if (message instanceof HandshakeMessage
                        && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    return action;
                }
            }
        }
        return null;
    }

    public static StaticReceivingAction getFirstStaticConfiguredReceiveAction(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticReceivingAction> actionList = trace.getStaticConfiguredReceivingActions();
        for (StaticReceivingAction action : actionList) {
            for (ProtocolMessage message : action.getExpectedList(ProtocolMessage.class)) {
                if (message instanceof HandshakeMessage
                        && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    return action;
                }
            }
        }
        return null;
    }

    public static StaticSendingAction getFirstStaticConfiguredSendAction(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticSendingAction> actionList = trace.getStaticConfiguredSendingActions();
        for (StaticSendingAction action : actionList) {
            for (ProtocolMessage message : action.getConfiguredList(ProtocolMessage.class)) {
                if (message.getProtocolMessageType() == type) {
                    return action;
                }
            }
        }
        return null;
    }

    public static ProtocolMessage getFirstStaticConfiguredReceiveMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredReceiveMessages(trace);
        for (ProtocolMessage message : messageList) {
            if (message.getProtocolMessageType() == type) {
                return message;
            }
        }
        return null;
    }

    public static HandshakeMessage getLastStaticConfiguredSendMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredSendMessages(trace);
        List<HandshakeMessage> filteredMessageList = new LinkedList<>();
        for (ProtocolMessage message : messageList) {
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                filteredMessageList.add((HandshakeMessage) message);
            }
        }
        if (filteredMessageList.isEmpty()) {
            return null;
        } else {
            return filteredMessageList.get(filteredMessageList.size() - 1);
        }
    }

    public static HandshakeMessage getLastStaticConfiguredReceiveMessage(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredReceiveMessages(trace);
        for (ProtocolMessage message : messageList) {
            if (message instanceof HandshakeMessage
                    && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                return (HandshakeMessage) message;
            }
        }
        return null;
    }

    public static ProtocolMessage getLastStaticConfiguredSendMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredSendMessages(trace);
        List<ProtocolMessage> filteredMessageList = new LinkedList<>();
        for (ProtocolMessage message : messageList) {
            if (message.getProtocolMessageType() == type) {
                filteredMessageList.add(message);
            }
        }
        if (filteredMessageList.isEmpty()) {
            return null;
        } else {
            return filteredMessageList.get(filteredMessageList.size() - 1);
        }
    }

    public static ProtocolMessage getLastStaticConfiguredReceiveMessage(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> messageList = getAllStaticConfiguredReceiveMessages(trace);
        List<ProtocolMessage> filteredMessageList = new LinkedList<>();
        for (ProtocolMessage message : messageList) {
            if (message.getProtocolMessageType() == type) {
                filteredMessageList.add(message);
            }
        }
        if (filteredMessageList.isEmpty()) {
            return null;
        } else {
            return filteredMessageList.get(filteredMessageList.size() - 1);
        }
    }

    public static StaticSendingAction getLastStaticConfiguredSendAction(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticSendingAction> actionList =
                getStaticSendingActionsWithConfiguration(trace, type);
        if (actionList.isEmpty()) {
            return null;
        } else {
            return actionList.get(actionList.size() - 1);
        }
    }

    public static StaticReceivingAction getLastStaticConfiguredReceiveAction(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticReceivingAction> actionList =
                getStaticReceivingActionsWithConfiguration(trace, type);
        if (actionList.isEmpty()) {
            return null;
        } else {
            return actionList.get(actionList.size() - 1);
        }
    }

    public static StaticSendingAction getLastStaticConfiguredSendAction(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticSendingAction> actionList =
                getStaticSendingActionsWithConfiguration(trace, type);
        if (actionList.isEmpty()) {
            return null;
        } else {
            return actionList.get(actionList.size() - 1);
        }
    }

    public static StaticReceivingAction getLastStaticConfiguredReceiveAction(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticReceivingAction> actionList =
                getStaticReceivingActionsWithConfiguration(trace, type);
        if (actionList.isEmpty()) {
            return null;
        } else {
            return actionList.get(actionList.size() - 1);
        }
    }

    public static List<StaticSendingAction> getStaticSendingActionsWithConfiguration(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticSendingAction> actions = new LinkedList<>();
        for (StaticSendingAction action : trace.getStaticConfiguredSendingActions()) {
            for (ProtocolMessage message : action.getConfiguredList(ProtocolMessage.class)) {
                if (message instanceof HandshakeMessage
                        && ((HandshakeMessage) message).getHandshakeMessageType() == type) {
                    actions.add(action);
                }
            }
        }
        return actions;
    }

    public static List<StaticReceivingAction> getStaticReceivingActionsWithConfiguration(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<StaticReceivingAction> actions = new LinkedList<>();
        for (StaticReceivingAction action : trace.getStaticConfiguredReceivingActions()) {
            for (ProtocolMessage message : action.getExpectedList(ProtocolMessage.class)) {
                if (message instanceof HandshakeMessage) {
                    if (((HandshakeMessage) message).getHandshakeMessageType() == type) {
                        actions.add(action);
                    }
                }
            }
        }
        return actions;
    }

    public static List<StaticSendingAction> getStaticSendingActionsWithConfiguration(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticSendingAction> actions = new LinkedList<>();
        for (StaticSendingAction action : trace.getStaticConfiguredSendingActions()) {
            for (ProtocolMessage message : action.getConfiguredList(ProtocolMessage.class)) {
                if (message.getProtocolMessageType() == type) {
                    actions.add(action);
                }
            }
        }
        return actions;
    }

    public static List<StaticReceivingAction> getStaticReceivingActionsWithConfiguration(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<StaticReceivingAction> actions = new LinkedList<>();
        for (StaticReceivingAction action : trace.getStaticConfiguredReceivingActions()) {
            for (ProtocolMessage message : action.getExpectedList(ProtocolMessage.class)) {
                if (message.getProtocolMessageType() == type) {
                    actions.add(action);
                }
            }
        }
        return actions;
    }

    public static List<ProtocolMessage> getStaticConfiguredSendMessages(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> sendMessages = getAllStaticConfiguredSendMessages(trace);
        Iterator<ProtocolMessage> iterator = sendMessages.iterator();
        while (iterator.hasNext()) {
            ProtocolMessage message = iterator.next();
            if (message.getProtocolMessageType() != type) {
                iterator.remove();
            }
        }
        return sendMessages;
    }

    public static List<ProtocolMessage> getStaticConfiguredReceiveMessages(
            WorkflowTrace trace, ProtocolMessageType type) {
        List<ProtocolMessage> receiveMessages = getAllStaticConfiguredReceiveMessages(trace);
        Iterator<ProtocolMessage> iterator = receiveMessages.iterator();
        while (iterator.hasNext()) {
            ProtocolMessage message = iterator.next();
            if (message.getProtocolMessageType() != type) {
                iterator.remove();
            }
        }
        return receiveMessages;
    }

    public static List<ProtocolMessage> getStaticConfiguredSendMessages(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> sendMessages = getAllStaticConfiguredSendMessages(trace);
        Iterator<ProtocolMessage> iterator = sendMessages.iterator();
        while (iterator.hasNext()) {
            ProtocolMessage message = iterator.next();
            if (message instanceof HandshakeMessage) {
                if (((HandshakeMessage) message).getHandshakeMessageType() != type) {
                    iterator.remove();
                }
            }
        }
        return sendMessages;
    }

    public static List<ProtocolMessage> getStaticConfiguredReceiveMessages(
            WorkflowTrace trace, HandshakeMessageType type) {
        List<ProtocolMessage> receiveMessages = getAllStaticConfiguredReceiveMessages(trace);
        Iterator<ProtocolMessage> iterator = receiveMessages.iterator();
        while (iterator.hasNext()) {
            ProtocolMessage message = iterator.next();
            if (message instanceof HandshakeMessage) {
                if (((HandshakeMessage) message).getHandshakeMessageType() != type) {
                    iterator.remove();
                }
            }
        }
        return receiveMessages;
    }

    public static List<ProtocolMessage> getAllStaticConfiguredSendMessages(WorkflowTrace trace) {
        List<ProtocolMessage> sendMessages = new LinkedList<>();
        for (StaticSendingAction action : trace.getStaticConfiguredSendingActions()) {
            List<List<DataContainer>> configuredDataContainerLists =
                    action.getConfiguredDataContainerLists();
            for (List<DataContainer> dataContainerList : configuredDataContainerLists) {
                for (DataContainer dataContainer : dataContainerList) {
                    if (dataContainer instanceof ProtocolMessage) {
                        sendMessages.add((ProtocolMessage) dataContainer);
                    }
                }
            }
        }
        return sendMessages;
    }

    public static List<ProtocolMessage> getAllStaticConfiguredReceiveMessages(WorkflowTrace trace) {
        List<ProtocolMessage> receiveMessages = new LinkedList<>();
        for (StaticReceivingAction action : trace.getStaticConfiguredReceivingActions()) {
            List<List<DataContainer>> configuredDataContainerLists =
                    action.getExpectedDataContainerLists();
            for (List<DataContainer> dataContainerList : configuredDataContainerLists) {
                for (DataContainer dataContainer : dataContainerList) {
                    if (dataContainer instanceof ProtocolMessage) {
                        receiveMessages.add((ProtocolMessage) dataContainer);
                    }
                }
            }
        }
        return receiveMessages;
    }
}
