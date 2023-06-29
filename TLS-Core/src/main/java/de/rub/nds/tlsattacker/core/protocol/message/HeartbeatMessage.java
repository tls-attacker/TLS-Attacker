/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HeartbeatMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HeartbeatMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HeartbeatMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HeartbeatMessageSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Objects;

@XmlRootElement(name = "Heartbeat")
public class HeartbeatMessage extends ProtocolMessage<HeartbeatMessage> {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    ModifiableByte heartbeatMessageType;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    ModifiableInteger payloadLength;

    @ModifiableVariableProperty() ModifiableByteArray payload;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    ModifiableByteArray padding;

    public HeartbeatMessage() {
        super();
        this.protocolMessageType = ProtocolMessageType.HEARTBEAT;
    }

    public ModifiableByte getHeartbeatMessageType() {
        return heartbeatMessageType;
    }

    public void setHeartbeatMessageType(ModifiableByte heartbeatMessageType) {
        this.heartbeatMessageType = heartbeatMessageType;
    }

    public void setHeartbeatMessageType(byte heartbeatMessageType) {
        this.heartbeatMessageType =
                ModifiableVariableFactory.safelySetValue(
                        this.heartbeatMessageType, heartbeatMessageType);
    }

    public ModifiableInteger getPayloadLength() {
        return payloadLength;
    }

    public void setPayloadLength(ModifiableInteger payloadLength) {
        this.payloadLength = payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
        this.payloadLength =
                ModifiableVariableFactory.safelySetValue(this.payloadLength, payloadLength);
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
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HeartbeatMessage:");
        sb.append("\n  Type: ");
        if (heartbeatMessageType != null && heartbeatMessageType.getValue() != null) {
            sb.append(
                    HeartbeatMessageType.getHeartbeatMessageType(heartbeatMessageType.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Payload Length: ");
        if (payloadLength != null && payloadLength.getValue() != null) {
            sb.append(payloadLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Payload: ");
        if (payload != null && payload.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(payload.getValue()));
        } else {
            sb.append("null");
        }
        sb.append("\n  Padding: ");
        if (padding != null && padding.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(padding.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toCompactString() {
        return "HEARTBEAT";
    }

    @Override
    public String toShortString() {
        return "HB";
    }

    @Override
    public HeartbeatMessageHandler getHandler(TlsContext tlsContext) {
        return new HeartbeatMessageHandler(tlsContext);
    }

    @Override
    public HeartbeatMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new HeartbeatMessageParser(stream);
    }

    @Override
    public HeartbeatMessagePreparator getPreparator(TlsContext tlsContext) {
        return new HeartbeatMessagePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public HeartbeatMessageSerializer getSerializer(TlsContext tlsContext) {
        return new HeartbeatMessageSerializer(this);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 59 * hash + Objects.hashCode(this.heartbeatMessageType);
        hash = 59 * hash + Objects.hashCode(this.payloadLength);
        hash = 59 * hash + Objects.hashCode(this.payload);
        hash = 59 * hash + Objects.hashCode(this.padding);
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
        final HeartbeatMessage other = (HeartbeatMessage) obj;
        if (!Objects.equals(this.heartbeatMessageType, other.heartbeatMessageType)) {
            return false;
        }
        if (!Objects.equals(this.payloadLength, other.payloadLength)) {
            return false;
        }
        if (!Objects.equals(this.payload, other.payload)) {
            return false;
        }
        return Objects.equals(this.padding, other.padding);
    }
}
