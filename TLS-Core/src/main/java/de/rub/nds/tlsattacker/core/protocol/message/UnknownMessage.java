/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.TlsMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "UnknownMessage")
public class UnknownMessage extends TlsMessage {

    private byte[] dataConfig;

    private ProtocolMessageType recordContentMessageType;

    public UnknownMessage() {
        this.recordContentMessageType = ProtocolMessageType.UNKNOWN;
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public UnknownMessage(Config config) {
        super();
        this.recordContentMessageType = ProtocolMessageType.UNKNOWN;
        protocolMessageType = ProtocolMessageType.HANDSHAKE;
    }

    public UnknownMessage(Config config, ProtocolMessageType recordContentMessageType) {
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
    public TlsMessageHandler getHandler(TlsContext context) {
        return new UnknownMessageHandler(context, recordContentMessageType);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("UnknownMessage:");
        sb.append("\n  Data: ");
        if (getCompleteResultingMessage() != null && getCompleteResultingMessage().getValue() != null) {
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
}
