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
import de.rub.nds.tlsattacker.core.protocol.handler.UnknownSSL2MessageHandler;
import de.rub.nds.tlsattacker.core.protocol.parser.UnknownSSL2MessageParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.UnknownSSL2MessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.UnknownSSL2MessageSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

@XmlRootElement(name = "UnknownSSL2Message")
public class UnknownSSL2Message extends SSL2Message {

    private byte[] dataConfig;

    public UnknownSSL2Message() {
        super(SSL2MessageType.SSL_UNKNOWN);
    }

    public UnknownSSL2Message(byte[] config) {
        super(SSL2MessageType.SSL_UNKNOWN);
        this.dataConfig = config;
    }

    public byte[] getDataConfig() {
        return dataConfig;
    }

    public void setDataConfig(byte[] config) {
        this.dataConfig = config;
    }

    @Override
    public String toShortString() {
        return "UnknownSSL2";
    }

    @Override
    public UnknownSSL2MessageParser getParser(TlsContext tlsContext, InputStream stream) {
        return new UnknownSSL2MessageParser(stream, tlsContext);
    }

    @Override
    public UnknownSSL2MessagePreparator getPreparator(TlsContext tlsContext) {
        return new UnknownSSL2MessagePreparator(tlsContext.getChooser(), this);
    }

    @Override
    public UnknownSSL2MessageSerializer getSerializer(TlsContext tlsContext) {
        return new UnknownSSL2MessageSerializer(this);
    }

    @Override
    public UnknownSSL2MessageHandler getHandler(TlsContext tlsContext) {
        return new UnknownSSL2MessageHandler(tlsContext);
    }

    @Override
    public String toCompactString() {
        return toShortString();
    }
}
