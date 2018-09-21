/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestSerializer extends HandshakeMessageSerializer<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HelloVerifyRequestMessage msg;

    /**
     * Constructor for the HelloVerifyRequestSerializer
     *
     * @param message
     *            Message that should be serialized
     * @param version
     *            Version of the Protocol
     */
    public HelloVerifyRequestSerializer(HelloVerifyRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        LOGGER.debug("Serializing HelloVerifiyRequestMessage");
        writeProtocolVersion(msg);
        writeCookieLength(msg);
        writeCookie(msg);
        return getAlreadySerialized();
    }

    /**
     * Writes the ProtocolVersion of the HelloVerifyMessage into the final
     * byte[]
     */
    private void writeProtocolVersion(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: " + ArrayConverter.bytesToHexString(msg.getProtocolVersion().getValue()));
    }

    /**
     * Writes the CookieLength of the HelloVerifyMessage into the final byte[]
     */
    private void writeCookieLength(HelloVerifyRequestMessage msg) {
        appendByte(msg.getCookieLength().getValue());
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    /**
     * Writes the Cookie of the HelloVerifyMessage into the final byte[]
     */
    private void writeCookie(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: " + ArrayConverter.bytesToHexString(msg.getCookie().getValue()));
    }

}
