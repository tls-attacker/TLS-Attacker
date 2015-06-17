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
package de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.handlers.HeartbeatHandler;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class HeartbeatMessage extends ProtocolMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte heartbeatMessageType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger payloadLength;

    @ModifiableVariableProperty()
    ModifiableByteArray payload;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    ModifiableByteArray padding;

    public HeartbeatMessage() {
	this.protocolMessageType = ProtocolMessageType.HEARTBEAT;
    }

    public HeartbeatMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableByte getHeartbeatMessageType() {
	return heartbeatMessageType;
    }

    public void setHeartbeatMessageType(ModifiableByte heartbeatMessageType) {
	this.heartbeatMessageType = heartbeatMessageType;
    }

    public void setHeartbeatMessageType(byte heartbeatMessageType) {
	this.heartbeatMessageType = ModifiableVariableFactory.safelySetValue(this.heartbeatMessageType,
		heartbeatMessageType);
    }

    public ModifiableInteger getPayloadLength() {
	return payloadLength;
    }

    public void setPayloadLength(ModifiableInteger payloadLength) {
	this.payloadLength = payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
	this.payloadLength = ModifiableVariableFactory.safelySetValue(this.payloadLength, payloadLength);
    }

    public ModifiableByteArray getPayload() {
	return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
	this.payload = payload;
    }

    public void setPayload(byte[] payload) {
	this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public ModifiableByteArray getPadding() {
	return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
	this.padding = padding;
    }

    public void setPadding(byte[] padding) {
	this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    @Override
    public ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext) {
	HeartbeatHandler hmh = new HeartbeatHandler(tlsContext);
	hmh.setProtocolMessage(this);
	return hmh;
    }

    @Override
    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("\nHeartbeat message:");
	return sb.toString();
    }

}
