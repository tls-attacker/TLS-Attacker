/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ServerHelloDoneMessage extends HandshakeMessage {

    public ServerHelloDoneMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.SERVER_HELLO_DONE);
    }

    public ServerHelloDoneMessage() {
        super(HandshakeMessageType.SERVER_HELLO_DONE);
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new ServerHelloDoneHandler(context);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ServerHelloDoneMessage:");
        return sb.toString();
    }
}
