/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.heartbeat;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.heartbeat.HeartbeatHandler;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;

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
	sb.append("\nHeartbeat message:\n  Type: ");
	sb.append(HeartbeatMessageType.getHeartbeatMessageType(heartbeatMessageType.getValue()));
	sb.append("\n  Payload Length: ");
	if (payloadLength != null) {
	    sb.append(payloadLength.getValue());
	} else {
	    sb.append("null");
	}
	sb.append("\n  Payload: ");
	if (payload != null) {
	    sb.append(ArrayConverter.bytesToHexString(payload.getValue()));
	} else {
	    sb.append("null");
	}
	sb.append("\n  Padding: ");
	if (padding != null) {
	    sb.append(ArrayConverter.bytesToHexString(padding.getValue()));
	} else {
	    sb.append("null");
	}
	return sb.toString();
    }

    @Override
    public String toCompactString() {
	return "Heartbeat";
    }

}
