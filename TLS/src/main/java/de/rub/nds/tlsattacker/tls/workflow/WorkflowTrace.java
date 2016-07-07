/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ArbitraryMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HelloRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A wrapper class over a list of protocol messages maintained in the TLS
 * context.
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
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
	    @XmlElement(type = ArbitraryMessage.class, name = "ArbitraryMessage"),
	    @XmlElement(type = CertificateMessage.class, name = "Certificate"),
	    @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
	    @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
	    @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
	    @XmlElement(type = ClientHelloDtlsMessage.class, name = "DtlsClientHello"),
	    @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
	    @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
	    @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
	    @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
	    @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
	    @XmlElement(type = FinishedMessage.class, name = "Finished"),
	    @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
	    @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
	    @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
	    @XmlElement(type = AlertMessage.class, name = "Alert"),
	    @XmlElement(type = ApplicationMessage.class, name = "Application"),
	    @XmlElement(type = ChangeCipherSpecMessage.class, name = "ChangeCipherSpec"),
	    @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat"),
	    @XmlElement(type = HelloRequestMessage.class, name = "HelloRequest") })
    private List<ProtocolMessage> protocolMessages;

    private String name;

    private ProtocolVersion protocolVersion;

    /**
     * Swaps Server Messages with ArbitaryMessages
     */
    public void makeGeneric() {
	List<ProtocolMessage> tempList = getProtocolMessages();

	for (int i = 0; i < tempList.size(); i++) {
	    ArbitraryMessage arbitraryMessage = new ArbitraryMessage();
	    arbitraryMessage.setMessageIssuer(ConnectionEnd.SERVER);
	    if (tempList.get(i).getMessageIssuer() == ConnectionEnd.SERVER) {
		tempList.set(i, arbitraryMessage);
	    }
	}
    }

    /**
     * Initializes the workflow trace with an empty list of protocol messages
     */
    public WorkflowTrace() {
	this.protocolMessages = new LinkedList<>();
    }

    /**
     * Adds protocol message to the list
     * 
     * @param pm
     * @return Returns true if the list was changed
     */
    public boolean add(ProtocolMessage pm) {
	return protocolMessages.add(pm);
    }

    public ProtocolMessage remove(int index) {
	return protocolMessages.remove(index);
    }

    public List<ProtocolMessage> getProtocolMessages() {
	return protocolMessages;
    }

    public void setProtocolMessages(List<ProtocolMessage> protocolMessages) {
	this.protocolMessages = protocolMessages;
    }

    /**
     * Returns a list of protocol messages of a specific type
     * 
     * @param type
     * @return
     */
    public List<Integer> getProtocolMessagePositions(ProtocolMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type) {
		positions.add(position);
	    }
	    position++;
	}
	return positions;
    }

    public boolean containsProtocolMessage(ProtocolMessageType type) {
	return !getProtocolMessagePositions(type).isEmpty();
    }

    /**
     * Returns the first protocol message of a specified type, which is
     * contained in the list of protocol messages. Throws an
     * IllegalArgumentException if no message is found.
     * 
     * @param type
     * @return
     */
    public ProtocolMessage getFirstProtocolMessage(ProtocolMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type) {
		return pm;
	    }
	}
	throw new IllegalArgumentException("The Workflow does not contain any " + type);
    }

    /**
     * Returns a list of handshake messages of a given type.
     * 
     * @param type
     * @return
     */
    public List<Integer> getHandshakeMessagePositions(HandshakeMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type) {
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
     * contained in the list of protocol messages. Throws an
     * IllegalArgumentException if no message is found.
     * 
     * @param type
     * @return
     */
    public HandshakeMessage getFirstHandshakeMessage(HandshakeMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type) {
		    return hm;
		}
	    }
	}
	throw new IllegalArgumentException("The Workflow does not contain any " + type);
    }

    public ProtocolMessage getLastProtocolMesssage() {
	int size = protocolMessages.size();
	return protocolMessages.get(size - 1);
    }

    private List<ProtocolMessage> getMessages(ConnectionEnd peer) {
	List<ProtocolMessage> messages = new LinkedList<>();
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getMessageIssuer() == peer) {
		messages.add(pm);
	    }
	}
	return messages;
    }

    public List<ProtocolMessage> getClientMessages() {
	return getMessages(ConnectionEnd.CLIENT);
    }

    public List<ProtocolMessage> getServerMessages() {
	return getMessages(ConnectionEnd.SERVER);
    }

    public ProtocolMessage getLastClientMesssage() {
	List<ProtocolMessage> clientMessages = getClientMessages();
	int size = clientMessages.size();
	return clientMessages.get(size - 1);
    }

    public ProtocolMessage getLastServerMesssage() {
	List<ProtocolMessage> serverMessages = getServerMessages();
	int size = serverMessages.size();
	return serverMessages.get(size - 1);
    }

    private boolean containsFinishedMessage(ConnectionEnd peer) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {
		    if (hm.getMessageIssuer() == peer) {
			return true;
		    }
		}
	    }
	}
	return false;
    }

    public boolean containsClientFinished() {
	return containsFinishedMessage(ConnectionEnd.CLIENT);
    }

    public boolean containsServerFinished() {
	return containsFinishedMessage(ConnectionEnd.SERVER);
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
