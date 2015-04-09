/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessage;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ProtocolMessageTypeHolder {

    private ProtocolMessageType protocolMessageType;

    private HandshakeMessageType handshakeMessageType;

    public ProtocolMessageTypeHolder(byte value) {
	this.protocolMessageType = ProtocolMessageType.getContentType(value);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType value) {
	this.protocolMessageType = value;
    }

    public ProtocolMessageTypeHolder(byte protocolMessageType, byte handshakeMessageType) {
	this.protocolMessageType = ProtocolMessageType.getContentType(protocolMessageType);
	this.handshakeMessageType = HandshakeMessageType.getMessageType(handshakeMessageType);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType protocolMessageType, HandshakeMessageType handshakeMessageType) {
	this.protocolMessageType = protocolMessageType;
	this.handshakeMessageType = handshakeMessageType;
    }

    public ProtocolMessageTypeHolder(ProtocolMessage protocolMessage) {
	this.protocolMessageType = protocolMessage.getProtocolMessageType();
	if (protocolMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
	    this.handshakeMessageType = ((HandshakeMessage) protocolMessage).getHandshakeMessageType();
	}
    }

    public ProtocolMessageType getContentType() {
	return protocolMessageType;
    }

    public void setContentType(ProtocolMessageType contentType) {
	this.protocolMessageType = contentType;
    }

    public HandshakeMessageType getHandshakeMessageType() {
	return handshakeMessageType;
    }

    public void setHandshakeMessageType(HandshakeMessageType handshakeMessageType) {
	this.handshakeMessageType = handshakeMessageType;
    }

    @Override
    public boolean equals(Object obj) {
	if (obj == null) {
	    return false;
	}
	if (!(obj instanceof ProtocolMessageTypeHolder)) {
	    return false;
	}
	ProtocolMessageTypeHolder pmth = (ProtocolMessageTypeHolder) obj;
	return protocolMessageType == pmth.protocolMessageType && handshakeMessageType == pmth.handshakeMessageType;
    }

}
