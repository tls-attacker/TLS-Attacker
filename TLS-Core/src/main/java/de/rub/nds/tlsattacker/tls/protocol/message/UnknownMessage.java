/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.message;

import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handler.UnknownMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.tls.protocol.serializer.UnknownMessageSerializer;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.modifiablevariable.util.ArrayConverter;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class UnknownMessage extends ProtocolMessage {

    private byte[] dataConfig;

    public UnknownMessage() {
        super();
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public UnknownMessage(TlsConfig config) {
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
        return new UnknownMessageHandler(context);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        sb.append("   \nData").append(ArrayConverter.bytesToHexString(getCompleteResultingMessage().getValue()));
        return sb.toString();
    }
}
