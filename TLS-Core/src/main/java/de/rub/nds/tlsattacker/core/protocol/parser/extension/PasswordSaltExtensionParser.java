/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordSaltExtensionParser extends ExtensionParser<PasswordSaltExtensionMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public PasswordSaltExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(PasswordSaltExtensionMessage msg) {
        LOGGER.debug("Parsing PasswordSaltExtensionMessage");
        parseSaltLength(msg);
        parseSalt(msg);
    }

    @Override
    protected PasswordSaltExtensionMessage createExtensionMessage() {
        return new PasswordSaltExtensionMessage();
    }

    private void parseSaltLength(PasswordSaltExtensionMessage msg) {
        msg.setSaltLength(parseIntField(ExtensionByteLength.PASSWORD_SALT));
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    private void parseSalt(PasswordSaltExtensionMessage msg) {
        msg.setSalt(parseByteArrayField(msg.getSaltLength().getValue()));
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt()));
    }
}
