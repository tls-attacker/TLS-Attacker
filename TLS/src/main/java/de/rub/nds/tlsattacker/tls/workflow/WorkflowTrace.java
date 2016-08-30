/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.tls.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.tls.workflow.action.SendAction;
import de.rub.nds.tlsattacker.tls.workflow.action.TLSAction;
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
	    @XmlElement(type = MessageAction.class, name = "MessageAction"),
	    @XmlElement(type = SendAction.class, name = "SendAction"),
	    @XmlElement(type = ReceiveAction.class, name = "ReceiveAction"), })
    private List<TLSAction> tlsActions;

    private String name = null;
    private String description = null;
    private ProtocolVersion protocolVersion;

    /**
     * Swaps Server Messages with ArbitaryMessages
     */
    public void makeGeneric() {
	List<ProtocolMessage> tempList = getProtocolMessages();

	for (int i = 0; i < tempList.size(); i++) {

	    if (tempList.get(i).getMessageIssuer() == ConnectionEnd.SERVER) {
		ArbitraryMessage arbitraryMessage = new ArbitraryMessage();
		arbitraryMessage.setMessageIssuer(ConnectionEnd.SERVER);
		tempList.set(i, arbitraryMessage);
	    }
	}
    }

    /**
     * Initializes the workflow trace with an empty list of protocol
     * configuredMessages
     */
    public WorkflowTrace() {
	this.tlsActions = new LinkedList<>();
	this.protocolMessages = new LinkedList<>();
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

    /**
     * Returns a list of protocol configuredMessages of a specific type
     * 
     * @param type
     * @return
     */
    public List<Integer> getProtocolMessagePositions(ProtocolMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : getAllConfiguredMessages()) {
	    if (pm.getProtocolMessageType() == type) {
		positions.add(position);
	    }
	    position++;
	}
	return positions;
    }

    public List<Integer> getProtocolMessagePositions(ProtocolMessageType type, ConnectionEnd issuer) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type && pm.getMessageIssuer() == issuer) {
		positions.add(position);
	    }
	    position++;
	}
	return positions;
    }

    public boolean containsProtocolMessage(ProtocolMessageType type) {
	return !getProtocolMessagePositions(type).isEmpty();
    }

    public boolean containsProtocolMessage(ProtocolMessageType type, ConnectionEnd end) {
	return !getProtocolMessagePositions(type, end).isEmpty();
    }

    /**
     * Returns the first protocol message of a specified type, which is
     * contained in the list of protocol messages. Returns null if no message is found.
     * 
     * @param type
     * @return
     */
    public ProtocolMessage getFirstProtocolMessage(ProtocolMessageType type) {
	for (ProtocolMessage pm : getAllConfiguredMessages()) {
	    if (pm.getProtocolMessageType() == type) {
		return pm;
	    }
	}
	return null;
    }

    /**
     * Returns a list of handshake configuredMessages of a given type.
     * 
     * @param type
     * @return
     */
    public List<Integer> getHandshakeMessagePositions(HandshakeMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (TLSAction action : tlsActions) {
	    if (action instanceof MessageAction) {
		for (ProtocolMessage pm : ((MessageAction) action).getConfiguredMessages()) {
		    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
			HandshakeMessage hm = (HandshakeMessage) pm;
			if (hm.getHandshakeMessageType() == type) {
			    positions.add(position);
			}
		    }

		}
	    }
	    position++;
	}
	return positions;
    }

    /**
     * Returns a list of handshake messages of a given type.
     * 
     * @param type
     * @param end
     * @return
     */
    public List<Integer> getHandshakeMessagePositions(HandshakeMessageType type, ConnectionEnd connectionEnd) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type && hm.getMessageIssuer() == connectionEnd) {
		    positions.add(position);
		}
	    }
	    position++;
	}
	return positions;
    }

    public boolean containsHandshakeMessage(HandshakeMessageType type) {
	return !getHandshakeMessagePositions(type).isEmpty();
    }

    /**
     * Returns the first handshake message of a specified type, which is
     * contained in the list of protocol messages. Returns null if no message is found.
     * 
     * @param type
     * @return
     */
    public HandshakeMessage getFirstConfiguredHandshakeMessage(HandshakeMessageType type) {
	for (TLSAction action : tlsActions) {
	    if (action instanceof MessageAction) {
		for (ProtocolMessage pm : ((MessageAction) action).getConfiguredMessages()) {
		    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
			HandshakeMessage hm = (HandshakeMessage) pm;
			if (hm.getHandshakeMessageType() == type) {
			    return hm;
			}
		    }
		}
	    }
	}
	return null;
    }

    public ProtocolMessage getLastConfiguredProtocolMesssage() {
	int size = getAllConfiguredMessages().size();
	return getAllConfiguredMessages().get(size - 1);
    }

    public List<ProtocolMessage> getAllConfiguredMessages() {
	List<ProtocolMessage> messages = new LinkedList<>();
	for (TLSAction action : tlsActions) {
	    if (action instanceof MessageAction) {
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

    public List<ProtocolMessage> getConfiguredReceivingMessages() {
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

    public List<ProtocolMessage> getActuallyReceivedMessages() {
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

    public List<ProtocolMessage> getConfiguredSendMessages() {
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

    public ProtocolMessage getLastSendMesssage() {
	List<ProtocolMessage> clientMessages = getConfiguredSendMessages();
	int size = clientMessages.size();
	return clientMessages.get(size - 1);
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

    public ProtocolMessage getLastReceiveMesssage() {
	List<ProtocolMessage> serverMessages = getConfiguredReceivingMessages();
	int size = serverMessages.size();
	return serverMessages.get(size - 1);
    }

    public boolean receivedFinished() {
	for (ProtocolMessage pm : getActuallyReceivedMessages()) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {

		    return true;

		}
	    }
	}
	return false;
    }

    public boolean sentFinished() {
	for (ProtocolMessage pm : getConfiguredSendMessages()) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {

		    return true;

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
	sb.append("WorkflowTrace:");
	for (ProtocolMessage pm : protocolMessages) {
	    sb.append("\n").append(pm.toCompactString());
	}
	return sb.toString();
    }

}
