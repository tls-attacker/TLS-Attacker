/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

@XmlRootElement(name = "UnknownMessage")
public class UnknownMessage extends ProtocolMessage {

    private byte[] dataConfig;

    private ProtocolMessageType recordContentMessageType;

    public UnknownMessage() {
        super();
        this.recordContentMessageType = ProtocolMessageType.UNKNOWN;
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public UnknownMessage(ProtocolMessageType recordContentMessageType) {
        super();
        this.recordContentMessageType = recordContentMessageType;
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public ProtocolMessageType getRecordContentMessageType() {
        return recordContentMessageType;
    }

    public void setRecordContentMessageType(ProtocolMessageType recordContentMessageType) {
        this.recordContentMessageType = recordContentMessageType;
    }

    @Override
    public String toCompactString() {
        return "UNKNOWN_MESSAGE";
    }

    @Override
    public UnknownMessageHandler getHandler(Context context) {
        return new UnknownMessageHandler(context.getTlsContext());
    }

    @Override
    public UnknownMessageParser getParser(Context context, InputStream stream) {
        return new UnknownMessageParser(stream);
    }

    @Override
    public UnknownMessagePreparator getPreparator(Context context) {
        return new UnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UnknownMessageSerializer getSerializer(Context context) {
        return new UnknownMessageSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnknownMessage:");
        sb.append("\n  Data: ");
        if (getCompleteResultingMessage() != null
                && getCompleteResultingMessage().getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(getCompleteResultingMessage().getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "?";
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Arrays.hashCode(this.dataConfig);
        hash = 79 * hash + Objects.hashCode(this.recordContentMessageType);
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
        final UnknownMessage other = (UnknownMessage) obj;
        if (!Arrays.equals(this.dataConfig, other.dataConfig)) {
            return false;
        }
        return this.recordContentMessageType == other.recordContentMessageType;
    }
}
