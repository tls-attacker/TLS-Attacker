/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ToggleEncryptionAction;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A wrapper class over a list of protocol configuredMessages maintained in the
 * TLS context.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    /**
     * Workflow
     */
    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = TLSAction.class, name = "TLSAction"),
            @XmlElement(type = SendAction.class, name = "SendAction"),
            @XmlElement(type = ReceiveAction.class, name = "ReceiveAction"),
            @XmlElement(type = ToggleEncryptionAction.class, name = "ToggleEncryptionAction"),
            @XmlElement(type = ChangeCipherSuiteAction.class, name = "ChangeCipherSuiteAction"),
            @XmlElement(type = ChangeClientCertificateAction.class, name = "ChangeClientCertAction"),
            @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompressionAction"),
            @XmlElement(type = ChangeMasterSecretAction.class, name = "ChangeMasterSecretAction"),
            @XmlElement(type = ChangePreMasterSecretAction.class, name = "ChangePreMasterSecretAction"),
            @XmlElement(type = ChangeProtocolVersionAction.class, name = "ChangeProtocolVersionAction"),
            @XmlElement(type = ChangeClientRandomAction.class, name = "ChangeClientRandomAction"),
            @XmlElement(type = ChangeServerCertificateAction.class, name = "ChangeServerCertAction"),
            @XmlElement(type = ChangeServerRandomAction.class, name = "ChangeServerRandomAction") })
    private List<TLSAction> tlsActions;

    private String name = null;
    private String description = null;
    private ProtocolVersion protocolVersion;

    /**
     * Initializes the workflow trace with an empty list of protocol
     * configuredMessages
     */
    public WorkflowTrace() {
        this.tlsActions = new LinkedList<>();
    }

    /**
     * Swaps Server Messages with ArbitaryMessages
     */
    public void makeGeneric() {
        for (ReceiveAction action : getReceiveActions()) {
            action.getConfiguredMessages().clear();
            action.getConfiguredMessages().add(new ArbitraryMessage());
        }
    }

    public void reset() {
        for (TLSAction action : getTLSActions()) {
            action.reset();
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Adds protocol message to the list
     * 
     * @param pm
     * @return Returns true if the list was changed
     */
    public boolean add(TLSAction action) {
        return tlsActions.add(action);
    }

    public void add(int position, TLSAction action) {
        tlsActions.add(position, action);
    }

    public TLSAction remove(int index) {
        return tlsActions.remove(index);
    }

    public List<ReceiveAction> getReceiveActions() {
        List<ReceiveAction> receiveActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceiveAction) {
                receiveActions.add((ReceiveAction) action);
            }
        }
        return receiveActions;
    }

    public List<SendAction> getSendActions() {
        List<SendAction> sendActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof SendAction) {
                sendActions.add((SendAction) action);
            }
        }
        return sendActions;
    }

    public List<TLSAction> getTLSActions() {
        return tlsActions;
    }

    public void setTLSActions(List<TLSAction> tlsActions) {
        this.tlsActions = tlsActions;
    }

    private List<ProtocolMessage> filterMessageList(List<ProtocolMessage> messages, ProtocolMessageType type) {
        List<ProtocolMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.getProtocolMessageType() == type) {
                returnedMessages.add(protocolMessage);
            }
        }
        return returnedMessages;
    }

    private List<HandshakeMessage> filterHandshakeMessagesFromList(List<ProtocolMessage> messages) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (ProtocolMessage protocolMessage : messages) {
            if (protocolMessage.isHandshakeMessage()) {
                returnedMessages.add((HandshakeMessage) protocolMessage);
            }
        }
        return returnedMessages;
    }

    private List<HandshakeMessage> filterMessageList(List<HandshakeMessage> messages, HandshakeMessageType type) {
        List<HandshakeMessage> returnedMessages = new LinkedList<>();
        for (HandshakeMessage handshakeMessage : messages) {
            if (handshakeMessage.getHandshakeMessageType() == type) {
                returnedMessages.add(handshakeMessage);
            }
        }
        return returnedMessages;
    }

    public List<ProtocolMessage> getActualReceivedProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllActuallyReceivedMessages(), type);
    }

    public ProtocolMessage getFirstConfiguredSendMessageOfType(ProtocolMessageType type) {
        return filterMessageList(getAllConfiguredSendMessages(), type).get(0);
    }

    public HandshakeMessage getFirstConfiguredSendMessageOfType(HandshakeMessageType type) {
        List<HandshakeMessage> list = filterMessageList(
                filterHandshakeMessagesFromList(getAllConfiguredSendMessages()), type);
        if (list.size() > 0) {
            return list.get(0);
        }
        return null;
    }

    public ProtocolMessage getFirstActuallySendMessageOfType(ProtocolMessageType type) {
        List<ProtocolMessage> list = filterMessageList(getAllActuallySentMessages(), type);
        if (list.size() > 0) {
            return list.get(0);
        }
        return null;
    }

    public HandshakeMessage getFirstActuallySendMessageOfType(HandshakeMessageType type) {
        return filterMessageList(filterHandshakeMessagesFromList(getAllActuallySentMessages()), type).get(0);
    }

    public List<HandshakeMessage> getActuallyRecievedHandshakeMessagesOfType(HandshakeMessageType type) {
        return filterMessageList(filterHandshakeMessagesFromList(getAllActuallyReceivedMessages()), type);
    }

    public List<ProtocolMessage> getActuallyRecievedProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllActuallyReceivedMessages(), type);
    }

    public List<HandshakeMessage> getActuallySentHandshakeMessagesOfType(HandshakeMessageType type) {
        return filterMessageList(filterHandshakeMessagesFromList(getAllActuallySentMessages()), type);
    }

    public List<ProtocolMessage> getActuallySentProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllActuallySentMessages(), type);
    }

    public List<HandshakeMessage> getConfiguredRecievedHandshakeMessagesOfType(HandshakeMessageType type) {
        return filterMessageList(filterHandshakeMessagesFromList(getAllConfiguredReceivingMessages()), type);
    }

    public List<ProtocolMessage> getConfiguredRecievedProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllConfiguredReceivingMessages(), type);
    }

    public List<HandshakeMessage> getConfiguredSentHandshakeMessagesOfType(HandshakeMessageType type) {
        return filterMessageList(filterHandshakeMessagesFromList(getAllConfiguredSendMessages()), type);
    }

    public List<ProtocolMessage> getConfiguredSendProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllConfiguredSendMessages(), type);
    }

    public List<ProtocolMessage> getAllConfiguredMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action.isMessageAction()) {
                for (ProtocolMessage pm : ((MessageAction) action).getConfiguredMessages()) {
                    messages.add(pm);
                }
            }
        }
        return messages;
    }

    public List<ProtocolMessage> getAllExecutedMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof MessageAction) {
                for (ProtocolMessage pm : ((MessageAction) action).getActualMessages()) {
                    messages.add(pm);
                }
            }
        }
        return messages;
    }

    public List<ProtocolMessage> getAllConfiguredReceivingMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceiveAction) {
                for (ProtocolMessage pm : ((MessageAction) action).getConfiguredMessages()) {

                    messages.add(pm);

                }
            }
        }
        return messages;
    }

    public List<ProtocolMessage> getAllActuallyReceivedMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceiveAction) {
                for (ProtocolMessage pm : ((ReceiveAction) action).getActualMessages()) {

                    messages.add(pm);

                }
            }
        }
        return messages;
    }

    public List<ProtocolMessage> getAllActuallySentMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof SendAction) {
                for (ProtocolMessage pm : ((SendAction) action).getActualMessages()) {

                    messages.add(pm);

                }
            }
        }
        return messages;
    }

    public List<ProtocolMessage> getAllConfiguredSendMessages() {
        List<ProtocolMessage> messages = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof SendAction) {
                for (ProtocolMessage pm : ((SendAction) action).getConfiguredMessages()) {
                    messages.add(pm);
                }
            }
        }
        return messages;
    }

    public TLSAction getLastAction() {
        int size = tlsActions.size();
        return tlsActions.get(size - 1);
    }

    public MessageAction getLastMessageAction() {
        for (int i = tlsActions.size() - 1; i > 0; i--) {
            if (tlsActions.get(i) instanceof MessageAction) {
                return (MessageAction) (tlsActions.get(i));
            }
        }
        return null;
    }

    public ProtocolMessage getLastConfiguredReceiveMesssage() {
        List<ProtocolMessage> messages = getAllConfiguredReceivingMessages();
        if (messages.size() > 0) {
            return messages.get(0);
        }
        return null;
    }

    public ProtocolMessage getLastConfiguredSendMesssage() {
        List<ProtocolMessage> clientMessages = getAllConfiguredSendMessages();
        int size = clientMessages.size();
        return clientMessages.get(size - 1);
    }

    public boolean containsConfiguredReceivedProtocolMessage(ProtocolMessageType type) {
        return !getConfiguredRecievedProtocolMessagesOfType(type).isEmpty();
    }

    public boolean containsConfiguredSendProtocolMessage(ProtocolMessageType type) {
        return !getConfiguredSendProtocolMessagesOfType(type).isEmpty();
    }

    public boolean actuallyReceivedTypeBeforeType(ProtocolMessageType before, ProtocolMessageType after) {
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) action;
                for (ProtocolMessage message : receiveAction.getActualMessages()) {
                    if (message.getProtocolMessageType() == before) {
                        return true;
                    }
                    if (message.getProtocolMessageType() == after) {
                        return false;
                    }
                }
            }
        }
        return false;
    }

    public boolean actuallyReceivedTypeBeforeType(ProtocolMessageType before, HandshakeMessageType after) {
        for (TLSAction action : tlsActions) {
            if (action instanceof ReceiveAction) {
                ReceiveAction receiveAction = (ReceiveAction) action;
                for (ProtocolMessage message : receiveAction.getActualMessages()) {
                    if (message.getProtocolMessageType() == before) {
                        return true;
                    }
                    if (message.isHandshakeMessage()) {
                        HandshakeMessage handshakeMessage = (HandshakeMessage) message;
                        if (handshakeMessage.getHandshakeMessageType() == after) {
                            return false;
                        }
                    }
                }
            }
        }
        return false;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("WorkflowTrace Configured Messages:");
        for (ProtocolMessage pm : getAllConfiguredMessages()) {
            sb.append("\n").append(pm.toCompactString());
        }
        return sb.toString();
    }

}
