/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloVerifyRequestParser extends HandshakeMessageParser<HelloVerifyRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HelloVerifyRequestParser(InputStream inputStream, TlsContext tlsContext) {
        super(inputStream, tlsContext);
    }

    @Override
    public void parse(HelloVerifyRequestMessage msg) {
        LOGGER.debug("Parsing HelloVerifyRequestMessage");
        parseProtocolVersion(msg);
        parseCookieLength(msg);
        parseCookie(msg);
    }

    private void parseProtocolVersion(HelloVerifyRequestMessage msg) {
        msg.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug("ProtocolVersion: {}", msg.getProtocolVersion().getValue());
    }

    private void parseCookieLength(HelloVerifyRequestMessage msg) {
        msg.setCookieLength(parseByteField(HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH));
        LOGGER.debug("CookieLength: {}", msg.getCookieLength().getValue());
    }

    private void parseCookie(HelloVerifyRequestMessage msg) {
        msg.setCookie(parseByteArrayField(msg.getCookieLength().getValue()));
        LOGGER.debug("Cookie: {}", msg.getCookie().getValue());
    }
}
