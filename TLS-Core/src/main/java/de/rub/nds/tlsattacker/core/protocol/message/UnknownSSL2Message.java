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
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "UnknownSSL2Message")
public class UnknownSSL2Message extends SSL2Message {

    public UnknownSSL2Message() {
        super(SSL2MessageType.SSL_UNKNOWN);
    }

    @Override
    public String toShortString() {
        return "UnknownSSL2";
    }

    @Override
    public UnknownMessageParser getParser(Context context, InputStream stream) {
        return new UnknownMessageParser(stream);
    }

    @Override
    public HandshakeMessagePreparator getPreparator(Context context) {
        throw new UnsupportedOperationException("No preparator available for Unknown SSL2 message");
    }

    @Override
    public HandshakeMessageSerializer getSerializer(Context context) {
        return null;
    }

    @Override
    public HandshakeMessageHandler getHandler(Context context) {
        return null;
    }

    @Override
    public String toCompactString() {
        return toShortString();
    }
}
