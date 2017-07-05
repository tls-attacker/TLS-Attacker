/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.ArbitraryMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCipherSuiteAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeClientRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeCompressionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangePreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerCertificateAction;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeServerRandomAction;
import de.rub.nds.tlsattacker.core.workflow.action.DeactivateEncryptionAction;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.RenegotiationAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TLSAction;
import de.rub.nds.tlsattacker.core.workflow.action.WaitingAction;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A wrapper class over a list of protocol configuredMessages.
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger(WorkflowTrace.class);
    /**
     * Workflow
     */
    @HoldsModifiableVariable
    @XmlElements(value = { @XmlElement(type = TLSAction.class, name = "TLSAction"),
            @XmlElement(type = SendAction.class, name = "SendAction"),
            @XmlElement(type = ReceiveAction.class, name = "ReceiveAction"),
            @XmlElement(type = DeactivateEncryptionAction.class, name = "DeactivateEncryptionAction"),
            @XmlElement(type = ChangeCipherSuiteAction.class, name = "ChangeCipherSuiteAction"),
            @XmlElement(type = ChangeClientCertificateAction.class, name = "ChangeClientCertAction"),
            @XmlElement(type = ChangeCompressionAction.class, name = "ChangeCompressionAction"),
            @XmlElement(type = ChangeMasterSecretAction.class, name = "ChangeMasterSecretAction"),
            @XmlElement(type = ChangePreMasterSecretAction.class, name = "ChangePreMasterSecretAction"),
            @XmlElement(type = WaitingAction.class, name = "Wait"),
            @XmlElement(type = ResetConnectionAction.class, name = "ResetConnection"),
            @XmlElement(type = ChangeProtocolVersionAction.class, name = "ChangeProtocolVersionAction"),
            @XmlElement(type = ChangeClientRandomAction.class, name = "ChangeClientRandomAction"),
            @XmlElement(type = ChangeServerCertificateAction.class, name = "ChangeServerCertAction"),
            @XmlElement(type = RenegotiationAction.class, name = "RenegotiationAction"),
            @XmlElement(type = ChangeServerRandomAction.class, name = "ChangeServerRandomAction") })
    private List<TLSAction> tlsActions;

    private String name = null;
    private String description = null;

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

    /**
     * Removes runtime values for more compact storage. This keeps only the
     * relevant information to reexecute a WorkflowTrace
     */
    public void strip() {
        this.reset();
        List<MessageAction> messageActions = getMessageActions();
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        for (MessageAction action : messageActions) {
            for (ProtocolMessage message : action.getActualMessages()) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
            for (ProtocolMessage message : action.getConfiguredMessages()) {
                holders.addAll(message.getAllModifiableVariableHolders());
            }
        }

        for (ModifiableVariableHolder holder : holders) {
            List<Field> fields = holder.getAllModifiableVariableFields();
            for (Field f : fields) {
                f.setAccessible(true);

                ModifiableVariable mv = null;
                try {
                    mv = (ModifiableVariable) f.get(holder);
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    LOGGER.warn("Could not retrieve ModifiableVariables");
                }
                if (mv != null) {
                    if (mv.getModification() != null) {
                        mv.setOriginalValue(null);
                    } else {
                        try {
                            f.set(holder, null);
                        } catch (IllegalArgumentException | IllegalAccessException ex) {
                            LOGGER.warn("Could not strip ModifiableVariable without Modification");
                        }
                    }
                }
            }
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

    public boolean add(TLSAction action) {
        return tlsActions.add(action);
    }

    public void add(int position, TLSAction action) {
        tlsActions.add(position, action);
    }

    public TLSAction remove(int index) {
        return tlsActions.remove(index);
    }

    public List<TLSAction> getTLSActions() {
        return tlsActions;
    }

    public void setTLSActions(List<TLSAction> tlsActions) {
        this.tlsActions = tlsActions;
    }

    public List<MessageAction> getMessageActions() {
        List<MessageAction> messageActions = new LinkedList<>();
        for (TLSAction action : tlsActions) {
            if (action instanceof MessageAction) {
                messageActions.add((MessageAction) action);
            }
        }
        return messageActions;
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

    public List<ProtocolMessage> getActualReceivedProtocolMessagesOfType(ProtocolMessageType type) {
        return filterMessageList(getAllActuallyReceivedMessages(), type);
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

    public List<ProtocolMessage> getAllActualMessages() {
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
                for (ProtocolMessage pm : ((MessageAction) action).getActualMessages()) {

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
                for (ProtocolMessage pm : ((MessageAction) action).getConfiguredMessages()) {
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
                for (ProtocolMessage pm : ((MessageAction) action).getActualMessages()) {
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

    public boolean configuredLooksLikeActual() {
        for (TLSAction action : tlsActions) {
            if (action instanceof MessageAction) {
                MessageAction messageAction = (MessageAction) action;
                if (!messageAction.configuredLooksLikeActual()) {
                    return false;
                }
            }
        }
        return true;
    }

    public SendAction getFirstConfiguredSendActionWithType(ProtocolMessageType type) {
        for (TLSAction action : tlsActions) {
            if (action instanceof SendAction) {
                SendAction sendAction = (SendAction) action;
                for (ProtocolMessage message : sendAction.getConfiguredMessages()) {
                    if (message.getProtocolMessageType() == type) {
                        return sendAction;
                    }
                }
            }
        }
        return null;
    }

    public SendAction getFirstConfiguredSendActionWithType(HandshakeMessageType type) {
        for (TLSAction action : tlsActions) {
            if (action instanceof SendAction) {
                SendAction sendAction = (SendAction) action;
                List<HandshakeMessage> messages = filterHandshakeMessagesFromList(sendAction.getConfiguredMessages());
                if (!filterMessageList(messages, type).isEmpty()) {
                    return sendAction;
                }
            }
        }
        return null;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Trace Actions:");
        for (TLSAction action : tlsActions) {
            sb.append("\n");
            sb.append(action.toString());
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 23 * hash + Objects.hashCode(this.tlsActions);
        hash = 23 * hash + Objects.hashCode(this.name);
        hash = 23 * hash + Objects.hashCode(this.description);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final WorkflowTrace other = (WorkflowTrace) obj;
        if (!Objects.equals(this.name, other.name)) {
            return false;
        }
        if (!Objects.equals(this.description, other.description)) {
            return false;
        }
        return Objects.equals(this.tlsActions, other.tlsActions);
    }
}
