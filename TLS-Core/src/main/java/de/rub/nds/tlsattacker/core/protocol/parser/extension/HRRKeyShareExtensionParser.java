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
import de.rub.nds.tlsattacker.core.protocol.message.extension.HRRKeyShareExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HRRKeyShareExtensionParser extends ExtensionParser<HRRKeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HRRKeyShareExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(HRRKeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage");
        parseSelectedGroup(msg);
    }

    @Override
    protected HRRKeyShareExtensionMessage createExtensionMessage() {
        return new HRRKeyShareExtensionMessage();
    }

    /**
     * Reads the next bytes as the selectedGroup of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseSelectedGroup(HRRKeyShareExtensionMessage msg) {
        msg.setSelectedGroup(parseByteArrayField(ExtensionByteLength.KEY_SHARE_GROUP));
        LOGGER.debug("SelectedGroup: " + ArrayConverter.bytesToHexString(msg.getSelectedGroup().getValue()));
    }
}
