/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestSerializer
        extends HandshakeMessageSerializer<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HelloVerifyRequestMessage msg;

    /**
     * Constructor for the HelloVerifyRequestSerializer
     *
     * @param message Message that should be serialized
     */
    public HelloVerifyRequestSerializer(HelloVerifyRequestMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing HelloVerifyRequestMessage");
        writeProtocolVersion(msg);
        writeCookieLength(msg);
        writeCookie(msg);
        return getAlreadySerialized();
    }

    /** Writes the ProtocolVersion of the HelloVerifyMessage into the final byte[] */
    private void writeProtocolVersion(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }

    /** Writes the CookieLength of the HelloVerifyMessage into the final byte[] */
    private void writeCookieLength(HelloVerifyRequestMessage msg) {
        appendByte(msg.getCookieLength().getValue());
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    /** Writes the Cookie of the HelloVerifyMessage into the final byte[] */
    private void writeCookie(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: {}", msg.getCookie().getValue());
    }
}
