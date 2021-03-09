/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.HelloRetryRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HelloRetryRequestParser extends HandshakeMessageParser<HelloRetryRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HelloRetryRequestParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.HELLO_RETRY_REQUEST, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(HelloRetryRequestMessage msg) {
        LOGGER.debug("Parsing HelloRetryRequestMessage");
        parseProtocolVersion(msg);
        parseSelectedCipherSuite(msg);
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

    protected void parseSelectedCipherSuite(HelloRetryRequestMessage message) {
        message.setSelectedCipherSuite(parseByteArrayField(HandshakeByteLength.CIPHER_SUITE));
        LOGGER.debug("CipherSuite:" + ArrayConverter.bytesToHexString(message.getSelectedCipherSuite().getValue()));
    }

}
