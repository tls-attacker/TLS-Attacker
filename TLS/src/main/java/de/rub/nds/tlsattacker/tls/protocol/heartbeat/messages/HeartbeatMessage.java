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
package de.rub.nds.tlsattacker.tls.protocol.heartbeat.messages;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
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

    ModifiableVariable<Byte> heartbeatMessageType;

    ModifiableVariable<Integer> payloadLength;

    ModifiableVariable<byte[]> payload;

    ModifiableVariable<byte[]> padding;
    /**
     * resulting message
     */
    private ModifiableVariable<byte[]> completeResultingMessage;

    public HeartbeatMessage() {
	this.protocolMessageType = ProtocolMessageType.HEARTBEAT;
    }

    public HeartbeatMessage(ConnectionEnd messageIssuer) {
	this();
	this.messageIssuer = messageIssuer;
    }

    public ModifiableVariable<Byte> getHeartbeatMessageType() {
	return heartbeatMessageType;
    }

    public void setHeartbeatMessageType(ModifiableVariable<Byte> heartbeatMessageType) {
	this.heartbeatMessageType = heartbeatMessageType;
    }

    public void setHeartbeatMessageType(byte heartbeatMessageType) {
	if (this.heartbeatMessageType == null) {
	    this.heartbeatMessageType = new ModifiableVariable<>();
	}
	this.heartbeatMessageType.setOriginalValue(heartbeatMessageType);
    }

    public ModifiableVariable<Integer> getPayloadLength() {
	return payloadLength;
    }

    public void setPayloadLength(ModifiableVariable<Integer> payloadLength) {
	this.payloadLength = payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
	if (this.payloadLength == null) {
	    this.payloadLength = new ModifiableVariable<>();
	}
	this.payloadLength.setOriginalValue(payloadLength);
    }

    public ModifiableVariable<byte[]> getPayload() {
	return payload;
    }

    public void setPayload(ModifiableVariable<byte[]> payload) {
	this.payload = payload;
    }

    public void setPayload(byte[] payload) {
	if (this.payload == null) {
	    this.payload = new ModifiableVariable<>();
	}
	this.payload.setOriginalValue(payload);
    }

    public ModifiableVariable<byte[]> getPadding() {
	return padding;
    }

    public void setPadding(ModifiableVariable<byte[]> padding) {
	this.padding = padding;
    }

    public void setPadding(byte[] padding) {
	if (this.padding == null) {
	    this.padding = new ModifiableVariable<>();
	}
	this.padding.setOriginalValue(padding);
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

    public ModifiableVariable getCompleteResultingMessage() {
	return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableVariable<byte[]> completeResultingMessage) {
	this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
	this.completeResultingMessage = ModifiableVariableFactory.safelySetValue(this.completeResultingMessage,
		completeResultingMessage);
    }

}
