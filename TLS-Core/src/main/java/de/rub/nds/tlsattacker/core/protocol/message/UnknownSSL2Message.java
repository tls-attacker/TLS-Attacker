/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.tlsattacker.core.constants.SSL2MessageType;
import de.rub.nds.tlsattacker.core.layer.context.LayerContext;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownMessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
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
    public Parser getParser(LayerContext context, InputStream stream) {
        return new UnknownMessageParser(stream);
    }

    @Override
    public Preparator getPreparator(LayerContext context) {
        throw new UnsupportedOperationException("No preparator available for Unknown SSL2 message");
    }

    @Override
    public Serializer getSerializer(LayerContext context) {
        return null;
    }

    @Override
    public Handler getHandler(LayerContext context) {
        return null;
    }

    @Override
    public HandshakeMessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return null;
    }

    @Override
    public HandshakeMessagePreparator getPreparator(TlsContext tlsContext) {
        return null;
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
