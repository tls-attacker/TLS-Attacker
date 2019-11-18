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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.DraftKeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<KeyShareEntry> entryList;

    private final ExtensionType type;

    public KeyShareExtensionParser(int startposition, byte[] array, ExtensionType type) {
        super(startposition, array);
        this.type = type;
    }

    @Override
    public void parseExtensionMessageContent(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage");
        parseKeyShareListLength(msg);
        LOGGER.debug("Parsing KeyShareExtensionMessage");
        if (msg.getKeyShareListLength().getValue() + ExtensionByteLength.KEY_SHARE_LIST_LENGTH == msg
                .getExtensionLength().getValue()) {
            parseKeyShareListBytes(msg);
        } else {
            msg.setKeyShareListLength(msg.getExtensionLength().getValue());
            LOGGER.debug("KeyShareListLength: " + msg.getExtensionLength().getValue());
            setPointer(getPointer() - ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
            parseKeyShareListBytes(msg);
        }
        int position = 0;
        entryList = new LinkedList<>();
        while (position < msg.getKeyShareListLength().getValue()) {
            KeyShareEntryParser parser = new KeyShareEntryParser(position, msg.getKeyShareListBytes().getValue());
            entryList.add(parser.parse());
            if (position == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing KeySharePairs");
            }
            position = parser.getPointer();
        }
        parseKeyShareList(msg);
    }

    @Override
    protected KeyShareExtensionMessage createExtensionMessage() {
        if (type == ExtensionType.KEY_SHARE) {
            return new KeyShareExtensionMessage();
        } else {
            return new DraftKeyShareExtensionMessage();
        }
    }

    /**
     * Reads the next bytes as the keySahreListLength of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareListLength(KeyShareExtensionMessage msg) {
        msg.setKeyShareListLength(parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH));
        LOGGER.debug("KeyShareListLength: " + msg.getKeyShareListLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShareListBytes of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareListBytes(KeyShareExtensionMessage msg) {
        msg.setKeyShareListBytes(parseByteArrayField(msg.getKeyShareListLength().getValue()));
        LOGGER.debug("KeyShareListBytes: " + ArrayConverter.bytesToHexString(msg.getKeyShareListBytes().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareList of the Extension and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareList(KeyShareExtensionMessage msg) {
        msg.setKeyShareList(entryList);
    }
}
