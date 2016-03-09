/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
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
	    @XmlElement(type = CertificateMessage.class, name = "Certificate"),
	    @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
	    @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
	    @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
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
	    @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat") })
    private List<ProtocolMessage> protocolMessages;
    
    private String name;

    public List<ProtocolMessage> getProtocolMessages() {
	return protocolMessages;
    }

    public void setProtocolMessages(List<ProtocolMessage> protocolMessages) {
	this.protocolMessages = protocolMessages;
    }

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

    public ProtocolMessage getFirstProtocolMessage(ProtocolMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type) {
		return pm;
	    }
	}
	return null;
    }

    public HandshakeMessage getFirstHandshakeMessage(HandshakeMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type) {
		    return hm;
		}
	    }
	}
	return null;
    }

    public ProtocolMessage getLastProtocolMesssage() {
	int size = protocolMessages.size();
	return protocolMessages.get(size - 1);
    }
    
    private List<ProtocolMessage> getMessages(ConnectionEnd peer) {
        List<ProtocolMessage> messages = new LinkedList<>();
        for(ProtocolMessage pm : protocolMessages) {
            if(pm.getMessageIssuer() == peer) {
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
    
    private boolean containsFinishedMessage(ConnectionEnd peer) {
        for(ProtocolMessage pm : protocolMessages) {
            if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {
                    if(hm.getMessageIssuer() == peer) {
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

}
