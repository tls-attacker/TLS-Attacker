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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HRRKeyShareExtensionSerializer extends ExtensionSerializer<HRRKeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HRRKeyShareExtensionMessage msg;

    public HRRKeyShareExtensionSerializer(HRRKeyShareExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing HRRKeyShareExtensionMessage");
        writeSelectedGroup(msg);
        return getAlreadySerialized();
    }

    private void writeSelectedGroup(HRRKeyShareExtensionMessage msg) {
        appendBytes(msg.getSelectedGroup().getValue());
        LOGGER.debug("SelectedGroup: " + ArrayConverter.bytesToHexString(msg.getSelectedGroup().getValue()));
    }
}
