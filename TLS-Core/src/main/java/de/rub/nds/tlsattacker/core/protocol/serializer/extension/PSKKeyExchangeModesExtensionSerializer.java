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
import de.rub.nds.tlsattacker.core.protocol.message.extension.PSKKeyExchangeModesExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class PSKKeyExchangeModesExtensionSerializer extends ExtensionSerializer<PSKKeyExchangeModesExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PSKKeyExchangeModesExtensionMessage msg;

    public PSKKeyExchangeModesExtensionSerializer(PSKKeyExchangeModesExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing PSKKeyExchangeModesExtensionMessage");
        writeKeyExchangeModesListLength(msg);
        writeKeyExchangeModesListBytes(msg);
        return getAlreadySerialized();
    }

    private void writeKeyExchangeModesListLength(PSKKeyExchangeModesExtensionMessage msg) {
        appendInt(msg.getKeyExchangeModesListLength().getValue(), ExtensionByteLength.PSK_KEY_EXCHANGE_MODES_LENGTH);
        LOGGER.debug("KeyExchangeModesListLength: " + msg.getKeyExchangeModesListLength().getValue());
    }

    private void writeKeyExchangeModesListBytes(PSKKeyExchangeModesExtensionMessage msg) {
        appendBytes(msg.getKeyExchangeModesListBytes().getValue());
        LOGGER.debug("KeyExchangeModesListBytes: "
                + ArrayConverter.bytesToHexString(msg.getKeyExchangeModesListBytes().getValue()));
    }
}
