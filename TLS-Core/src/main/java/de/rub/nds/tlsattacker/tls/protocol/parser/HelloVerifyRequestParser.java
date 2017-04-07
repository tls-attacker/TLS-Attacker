/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestParser extends HandshakeMessageParser<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PARSER");

    public HelloVerifyRequestParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.HELLO_VERIFY_REQUEST, version);
    }

    @Override
    protected void parseHandshakeMessageContent(HelloVerifyRequestMessage msg) {
        parseProtocolVersion(msg);
        parseCookieLength(msg);
        parseCookie(msg);
    }

    @Override
    protected HelloVerifyRequestMessage createHandshakeMessage() {
        return new HelloVerifyRequestMessage();
    }

    private void parseProtocolVersion(HelloVerifyRequestMessage msg) {
        msg.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug("ProtcolVersion: " + Arrays.toString(msg.getProtocolVersion().getValue()));
    }

    private void parseCookieLength(HelloVerifyRequestMessage msg) {
        msg.setCookieLength(parseByteField(HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH));
        LOGGER.debug("CookieLength: " + msg.getCookieLength().getValue());
    }

    private void parseCookie(HelloVerifyRequestMessage msg) {
        msg.setCookie(parseByteArrayField(msg.getCookieLength().getValue()));
        LOGGER.debug("Cookie: " + Arrays.toString(msg.getCookie().getValue()));
    }

}
