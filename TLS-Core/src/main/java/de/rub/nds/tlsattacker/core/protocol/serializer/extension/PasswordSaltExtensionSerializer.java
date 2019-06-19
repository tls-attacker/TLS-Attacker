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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PasswordSaltExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PasswordSaltExtensionSerializer extends ExtensionSerializer<PasswordSaltExtensionMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final PasswordSaltExtensionMessage msg;

    public PasswordSaltExtensionSerializer(PasswordSaltExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing PasswordSaltExtensionMessage");
        writeSaltLength(msg);
        writeSalt(msg);
        return getAlreadySerialized();
    }

    private void writeSaltLength(PasswordSaltExtensionMessage msg) {
        appendInt(msg.getSaltLength().getValue(), ExtensionByteLength.PASSWORD_SALT);
        LOGGER.debug("SaltLength: " + msg.getSaltLength().getValue());
    }

    private void writeSalt(PasswordSaltExtensionMessage msg) {
        appendBytes(msg.getSalt().getValue());
        LOGGER.debug("Salt: " + ArrayConverter.bytesToHexString(msg.getSalt()));
    }
}
