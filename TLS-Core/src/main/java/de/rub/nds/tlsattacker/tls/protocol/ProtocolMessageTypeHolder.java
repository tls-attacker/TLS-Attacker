/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.tls.protocol.message.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.message.HandshakeMessage;
import java.util.Objects;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ProtocolMessageTypeHolder {

    private ProtocolMessageType protocolMessageType;

    private HandshakeMessageType handshakeMessageType;

    public ProtocolMessageTypeHolder(byte value) {
        this.protocolMessageType = ProtocolMessageType.getContentType(value);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType value) {
        this.protocolMessageType = value;
    }

    public ProtocolMessageTypeHolder(byte protocolMessageType, byte handshakeMessageType) {
        this.protocolMessageType = ProtocolMessageType.getContentType(protocolMessageType);
        this.handshakeMessageType = HandshakeMessageType.getMessageType(handshakeMessageType);
    }

    public ProtocolMessageTypeHolder(ProtocolMessageType protocolMessageType, HandshakeMessageType handshakeMessageType) {
        this.protocolMessageType = protocolMessageType;
        this.handshakeMessageType = handshakeMessageType;
    }

    public ProtocolMessageTypeHolder(ProtocolMessage protocolMessage) {
        this.protocolMessageType = protocolMessage.getProtocolMessageType();
        if (protocolMessage.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
            this.handshakeMessageType = ((HandshakeMessage) protocolMessage).getHandshakeMessageType();
        }
    }

    public ProtocolMessageType getContentType() {
        return protocolMessageType;
    }

    public void setContentType(ProtocolMessageType contentType) {
        this.protocolMessageType = contentType;
    }

    public HandshakeMessageType getHandshakeMessageType() {
        return handshakeMessageType;
    }

    public void setHandshakeMessageType(HandshakeMessageType handshakeMessageType) {
        this.handshakeMessageType = handshakeMessageType;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (!(obj instanceof ProtocolMessageTypeHolder)) {
            return false;
        }
        ProtocolMessageTypeHolder pmth = (ProtocolMessageTypeHolder) obj;
        return protocolMessageType == pmth.protocolMessageType && handshakeMessageType == pmth.handshakeMessageType;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 71 * hash + Objects.hashCode(this.protocolMessageType);
        hash = 71 * hash + Objects.hashCode(this.handshakeMessageType);
        return hash;
    }
}
