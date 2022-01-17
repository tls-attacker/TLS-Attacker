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
import de.rub.nds.tlsattacker.core.constants.TlsMessageType;
import de.rub.nds.tlsattacker.core.protocol.TlsMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.InputStream;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "UnknownMessage")
public class UnknownMessage extends TlsMessage {

    private byte[] dataConfig;

    private TlsMessageType recordContentMessageType;

    public UnknownMessage() {
        this.recordContentMessageType = TlsMessageType.UNKNOWN;
        protocolMessageType = TlsMessageType.UNKNOWN;
    }

    public UnknownMessage(Config config) {
        super();
        this.recordContentMessageType = TlsMessageType.UNKNOWN;
        protocolMessageType = TlsMessageType.HANDSHAKE;
    }

    public UnknownMessage(Config config, TlsMessageType recordContentMessageType) {
        super();
        this.recordContentMessageType = recordContentMessageType;
        protocolMessageType = TlsMessageType.UNKNOWN;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    public TlsMessageType getRecordContentMessageType() {
        return recordContentMessageType;
    }

    public void setRecordContentMessageType(TlsMessageType recordContentMessageType) {
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
    public UnknownMessageParser getParser(TlsContext context, InputStream stream) {
        return new UnknownMessageParser(stream, context.getChooser().getLastRecordVersion(), recordContentMessageType,
            context.getConfig());
    }

    @Override
    public UnknownMessagePreparator getPreparator(TlsContext context) {
        return new UnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UnknownMessageSerializer getSerializer(TlsContext context) {
        return new UnknownMessageSerializer(this, context.getChooser().getSelectedProtocolVersion());
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
