/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

/**
 * @author Nurullah Erinola
 */
public class HelloRetryRequestParser extends HandshakeMessageParser<HelloRetryRequestMessage> {

    public HelloRetryRequestParser(int pointer, byte[] array, ProtocolVersion version) {
        super(pointer, array, HandshakeMessageType.HELLO_RETRY_REQUEST, version);
    }

    @Override
    protected void parseHandshakeMessageContent(HelloRetryRequestMessage msg) {
        parseProtocolVersion(msg);
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg);
            }
        }
    }

    @Override
    protected HelloRetryRequestMessage createHandshakeMessage() {
        return new HelloRetryRequestMessage();
    }

    protected void parseProtocolVersion(HelloRetryRequestMessage message) {
        message.setProtocolVersion(parseByteArrayField(HandshakeByteLength.VERSION));
        LOGGER.debug("ProtocolVersion:" + ArrayConverter.bytesToHexString(message.getProtocolVersion().getValue()));
    }

}
