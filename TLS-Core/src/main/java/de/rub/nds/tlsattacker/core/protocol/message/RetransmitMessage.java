/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.RetransmitMessageHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 *
 *         Raw bytes of a previos send message retransmitted
 */
@XmlRootElement
public class RetransmitMessage extends ProtocolMessage {

    private byte[] bytesToTransmit = null;

    public RetransmitMessage() {
        REQUIRED_DEFAULT = false;
        protocolMessageType = ProtocolMessageType.UNKNOWN;
    }

    public RetransmitMessage(byte[] bytesToTransmit) {
        super();
        REQUIRED_DEFAULT = false;
        protocolMessageType = ProtocolMessageType.UNKNOWN;
        this.bytesToTransmit = bytesToTransmit;
    }

    @Override
    public String toCompactString() {
        return "Retransmitted Message";
    }

    public byte[] getBytesToTransmit() {
        return bytesToTransmit;
    }

    public void setBytesToTransmit(byte[] bytesToTransmit) {
        this.bytesToTransmit = bytesToTransmit;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new RetransmitMessageHandler(context);
    }
}
