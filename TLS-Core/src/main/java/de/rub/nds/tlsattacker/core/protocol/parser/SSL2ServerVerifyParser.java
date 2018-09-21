/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSL2ServerVerifyParser extends SSL2HandshakeMessageParser<SSL2ServerVerifyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SSL2ServerVerifyParser(byte[] message, int pointer, ProtocolVersion selectedProtocolVersion) {
        super(pointer, message, selectedProtocolVersion);
    }

    @Override
    protected SSL2ServerVerifyMessage parseMessageContent() {
        LOGGER.debug("Parsing SSL2ServerVerify");
        SSL2ServerVerifyMessage message = new SSL2ServerVerifyMessage();
        parseMessageLength(message);
        parseEncryptedPart(message);
        return message;
    }

    private void parseEncryptedPart(SSL2ServerVerifyMessage message) {
        message.setEncryptedPart(parseByteArrayField(message.getMessageLength().getValue()));
        LOGGER.debug("Encrypted Part: " + ArrayConverter.bytesToHexString(message.getEncryptedPart().getValue()));
    }

}
