/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Class which serializes the Extended Random Extension for Usage as in Handshake Messages, as defined as in
 * https://tools.ietf.org/html/draft-rescorla-tls-extended-random-02
 */
public class ExtendedRandomExtensionSerializer extends ExtensionSerializer<ExtendedRandomExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ExtendedRandomExtensionMessage message;

    public ExtendedRandomExtensionSerializer(ExtendedRandomExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        writeExtendedRandomLength(message);
        writeExtendedRandom(message);
        return getAlreadySerialized();
    }

    private void writeExtendedRandomLength(ExtendedRandomExtensionMessage msg) {
        appendInt(msg.getExtendedRandomLength().getValue(), ExtensionByteLength.EXTENDED_RANDOM_LENGTH);
        LOGGER.debug("ExtendedRandomLength: " + msg.getExtendedRandomLength().getValue());

    }

    private void writeExtendedRandom(ExtendedRandomExtensionMessage msg) {
        appendBytes(message.getExtendedRandom().getValue());
        LOGGER.debug(
            "Serialized Extended Random: " + ArrayConverter.bytesToHexString(msg.getExtendedRandom().getValue()));
    }
}
