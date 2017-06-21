/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlRootElement
public class HelloRequestMessage extends HandshakeMessage {

    public HelloRequestMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.HELLO_REQUEST);
        IS_INCLUDE_IN_DIGEST_DEFAULT = false;
    }

    public HelloRequestMessage() {
        super(HandshakeMessageType.HELLO_REQUEST);
        IS_INCLUDE_IN_DIGEST_DEFAULT = false;
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new HelloRequestHandler(context);
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
