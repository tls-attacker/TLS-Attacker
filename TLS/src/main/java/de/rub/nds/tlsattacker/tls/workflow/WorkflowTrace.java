/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.messages.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.FinishedMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages.HeartbeatMessage;
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
public class WorkflowTrace {

    /**
     * Workflow
     */
    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
	    @XmlElement(type = CertificateMessage.class, name = "Certificate"),
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

}
