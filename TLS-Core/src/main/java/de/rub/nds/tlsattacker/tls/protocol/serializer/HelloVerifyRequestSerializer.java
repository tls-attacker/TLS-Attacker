/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestSerializer extends HandshakeMessageSerializer<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("SERIALIZER");

    private HelloVerifyRequestMessage msg;

    public HelloVerifyRequestSerializer(HelloVerifyRequestMessage message, ProtocolVersion version) {
        super(message, version);
        this.msg = message;
    }

    @Override
    public byte[] serializeHandshakeMessageContent() {
        serializeProtocolVersion(msg);
        serializeCookieLength(msg);
        serializeCookie(msg);
        return getAlreadySerialized();
    }

    private void serializeProtocolVersion(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: "+ Arrays.toString(msg.getProtocolVersion().getValue()));
    }

    private void serializeCookieLength(HelloVerifyRequestMessage msg) {
        appendByte(msg.getCookieLength().getValue());
        LOGGER.debug("CookieLength: "+ msg.getCookieLength().getValue());
    }

    private void serializeCookie(HelloVerifyRequestMessage msg) {
        appendBytes(msg.getCookie().getValue());
        LOGGER.debug("Cookie: "+ Arrays.toString(msg.getCookie().getValue()));
    }

}
