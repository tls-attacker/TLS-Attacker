/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class UnknownMessage extends ProtocolMessage {

    private byte[] dataConfig;

    public UnknownMessage() {
        super();
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public UnknownMessage(Config config) {
        super();
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] dataConfig) {
        this.dataConfig = dataConfig;
    }

    @Override
    public String toCompactString() {
        return "UNKNOWN_MESSAGE";
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new UnknownHandler(context);
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
}
