/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "UnknownSSL2Message")
public class UnknownSSL2Message extends SSL2Message<UnknownMessage> {

    public UnknownSSL2Message() {
        super(SSL2MessageType.SSL_UNKNOWN);
    }

    @Override
    public String toShortString() {
        return "UnknownSSL2";
    }

    @Override
    public UnknownMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new UnknownMessageParser(stream);
    }

    @Override
    public HandshakeMessagePreparator getPreparator(TlsContext tlsContext) {
        throw new UnsupportedOperationException("No preparator available for Unknown SSL2 message");
    }

    @Override
    public HandshakeMessageSerializer getSerializer(TlsContext tlsContext) {
        return null;
    }

    @Override
    public HandshakeMessageHandler getHandler(TlsContext tlsContext) {
        return null;
    }

    @Override
    public String toCompactString() {
        return toShortString();
    }
}
