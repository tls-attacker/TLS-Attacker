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
import de.rub.nds.tlsattacker.core.protocol.handler.HelloRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.HelloRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.HelloRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HelloRequestSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "HelloRequest")
public class HelloRequestMessage extends HandshakeMessage<HelloRequestMessage> {

    public HelloRequestMessage() {
        super(HandshakeMessageType.HELLO_REQUEST);
        isIncludeInDigestDefault = false;
    }

    @Override
    public HelloRequestHandler getHandler(TlsContext tlsContext) {
        return new HelloRequestHandler(tlsContext);
    }

    @Override
    public HelloRequestParser getParser(TlsContext tlsContext, InputStream stream) {
        return new HelloRequestParser(stream, tlsContext);
    }

    @Override
    public HelloRequestPreparator getPreparator(TlsContext tlsContext) {
        return new HelloRequestPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public HelloRequestSerializer getSerializer(TlsContext tlsContext) {
        return new HelloRequestSerializer(this);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("HelloRequestMessage:");

        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "HR";
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
        int hash = 7;
        return hash;
    }
}
