/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;

public class EncryptedExtensionsParser extends HandshakeMessageParser<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedExtensionsParser(int pointer, byte[] array, ProtocolVersion version, Config config) {
        super(pointer, array, HandshakeMessageType.ENCRYPTED_EXTENSIONS, version, config);
    }

    @Override
    protected void parseHandshakeMessageContent(EncryptedExtensionsMessage msg) {
        LOGGER.debug("Parsing EncryptedExtensionsMessage");
        if (hasExtensionLengthField(msg)) {
            parseExtensionLength(msg);
            if (hasExtensions(msg)) {
                parseExtensionBytes(msg);
            } else {
                msg.setExtensions(new ArrayList<>());
            }
        }
    }

    @Override
    protected EncryptedExtensionsMessage createHandshakeMessage() {
        return new EncryptedExtensionsMessage();
    }

}
