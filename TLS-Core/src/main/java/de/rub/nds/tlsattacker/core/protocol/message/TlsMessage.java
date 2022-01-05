/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;
import java.util.List;

/**
 * TLS Protocol message is the message included in the Record message.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class TlsMessage extends ProtocolMessage {

    /**
     * content type
     */
    @XmlTransient
    protected ProtocolMessageType protocolMessageType;

    public TlsMessage() {
    }

    public ProtocolMessageType getProtocolMessageType() {
        return protocolMessageType;
    }

    public boolean isHandshakeMessage() {
        return this instanceof HandshakeMessage;
    }

    public boolean isDtlsHandshakeMessageFragment() {
        return this instanceof DtlsHandshakeMessageFragment;
    }

    @Override
    public boolean addToTypes(List<ProtocolMessageType> protocolMessageTypes) {
        return protocolMessageTypes.add(getProtocolMessageType());
    }
}
