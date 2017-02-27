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
import de.rub.nds.tlsattacker.tls.protocol.message.HelloVerifyRequestMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HelloVerifyRequestParser extends HandshakeMessageParser<HelloVerifyRequestMessage> {

    public HelloVerifyRequestParser(int pointer, byte[] array) {
        super(pointer, array, HandshakeMessageType.HELLO_VERIFY_REQUEST);
    }

    @Override
    public HelloVerifyRequestMessage parse() {
        HelloVerifyRequestMessage message = new HelloVerifyRequestMessage();
        parseType(message);
        parseLength(message);
        message.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        message.setCookieLength(parseByteField(HandshakeByteLength.DTLS_HANDSHAKE_COOKIE_LENGTH));
        message.setCookie(parseByteArrayField(message.getCookieLength().getValue()));
        message.setCompleteResultingMessage(getAlreadyParsed());
        return message;
    }

}
