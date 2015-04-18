/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.tls.protocol.handshake.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HandshakeMessage extends ProtocolMessage {

    HandshakeMessageType handshakeMessageType;

    /**
     * handshake type
     */
    @ModifiableVariableProperty
    ModifiableByte type;

    /**
     * length of the included handshake message (for example ClientHello)
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger length;

    public HandshakeMessage(HandshakeMessageType handshakeMessageType) {
	this.protocolMessageType = ProtocolMessageType.HANDSHAKE;
	this.handshakeMessageType = handshakeMessageType;
    }

    public ModifiableByte getType() {
	return type;
    }

    public ModifiableInteger getLength() {
	return length;
    }

    public void setType(ModifiableByte type) {
	this.type = type;
    }

    public void setLength(ModifiableInteger length) {
	this.length = length;
    }

    public void setType(Byte type) {
	this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public void setLength(int length) {
	this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public HandshakeMessageType getHandshakeMessageType() {
	return handshakeMessageType;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\n").append(handshakeMessageType.getName());
	sb.append("\n  Handshake Message Length: ").append(length.getValue());
	return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	ProtocolMessageHandler pmh = handshakeMessageType.getProtocolMessageHandler(tlsContext);
	pmh.setProtocolMessage(this);
	return pmh;
    }

}
