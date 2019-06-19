/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PWDProtectExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PWDProtectExtensionSerializer extends ExtensionSerializer<PWDProtectExtensionMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final PWDProtectExtensionMessage msg;

    public PWDProtectExtensionSerializer(PWDProtectExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing PWDProtectExtensionMessage");
        writeUsernameLength(msg);
        writeUsername(msg);
        return getAlreadySerialized();
    }

    private void writeUsernameLength(PWDProtectExtensionMessage msg) {
        appendInt(msg.getUsernameLength().getValue(), ExtensionByteLength.PWD_NAME);
        LOGGER.debug("UsernameLength: " + msg.getUsernameLength().getValue());
    }

    private void writeUsername(PWDProtectExtensionMessage msg) {
        appendBytes(msg.getUsername().getValue());
        LOGGER.debug("Username: " + ArrayConverter.bytesToHexString(msg.getUsername()));
    }
}
