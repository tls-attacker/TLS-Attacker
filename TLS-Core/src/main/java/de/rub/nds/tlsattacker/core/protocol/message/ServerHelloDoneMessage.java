/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.ServerHelloDoneHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloDoneParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.ServerHelloDonePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.ServerHelloDoneSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "ServerHelloDone")
public class ServerHelloDoneMessage extends HandshakeMessage<ServerHelloDoneMessage> {

    public ServerHelloDoneMessage() {
        super(HandshakeMessageType.SERVER_HELLO_DONE);
    }

    @Override
    public ServerHelloDoneHandler getHandler(TlsContext tlsContext) {
        return new ServerHelloDoneHandler(tlsContext);
    }

    @Override
    public ServerHelloDoneParser getParser(TlsContext tlsContext, InputStream stream) {
        return new ServerHelloDoneParser(stream, tlsContext);
    }

    @Override
    public ServerHelloDonePreparator getPreparator(TlsContext tlsContext) {
        return new ServerHelloDonePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public ServerHelloDoneSerializer getSerializer(TlsContext tlsContext) {
        return new ServerHelloDoneSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ServerHelloDoneMessage:");
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "SHD";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        return hash;
    }
}
