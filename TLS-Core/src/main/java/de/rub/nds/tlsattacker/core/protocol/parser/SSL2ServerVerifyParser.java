/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerVerifyParser extends SSL2HandshakeMessageParser<SSL2ServerVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerVerifyParser(byte[] message, int pointer, ProtocolVersion selectedProtocolVersion, Config config) {
        super(pointer, message, HandshakeMessageType.SSL2_SERVER_VERIFY, selectedProtocolVersion, config);
    }

    @Override
    protected SSL2ServerVerifyMessage parseMessageContent() {
        LOGGER.debug("Parsing SSL2ServerVerify");
        SSL2ServerVerifyMessage message = createHandshakeMessage();
        parseHandshakeMessageContent(message);
        return message;
    }

    @Override
    protected void parseHandshakeMessageContent(SSL2ServerVerifyMessage msg) {
        parseMessageLength(msg);
        parseEncryptedPart(msg);
    }

    @Override
    protected SSL2ServerVerifyMessage createHandshakeMessage() {
        return new SSL2ServerVerifyMessage();
    }

    private void parseEncryptedPart(SSL2ServerVerifyMessage message) {
        message.setEncryptedPart(parseByteArrayField(message.getMessageLength().getValue()));
        LOGGER.debug("Encrypted Part: " + ArrayConverter.bytesToHexString(message.getEncryptedPart().getValue()));
    }

}
