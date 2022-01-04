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
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "UnknownMessage")
public class UnknownMessage extends ProtocolMessage {

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
    public UnknownMessageHandler getHandler(TlsContext context) {
        return new UnknownMessageHandler(context, recordContentMessageType);
    }

    @Override
    public UnknownMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new UnknownMessageParser(stream, tlsContext.getChooser().getLastRecordVersion(),
            recordContentMessageType, tlsContext.getConfig());
    }

    @Override
    public UnknownMessagePreparator getPreparator(TlsContext tlsContext) {
        return new UnknownMessagePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public UnknownMessageSerializer getSerializer(TlsContext tlsContext) {
        return new UnknownMessageSerializer(this, tlsContext.getChooser().getSelectedProtocolVersion());
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
