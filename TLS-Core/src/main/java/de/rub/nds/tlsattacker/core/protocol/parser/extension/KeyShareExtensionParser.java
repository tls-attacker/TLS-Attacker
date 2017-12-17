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
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import java.util.LinkedList;
import java.util.List;

public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private List<KeySharePair> pairList;

    public KeyShareExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage");
        parseKeySahreListLength(msg);
        if (msg.getKeyShareListLength().getValue() + ExtensionByteLength.KEY_SHARE_LIST_LENGTH == msg
                .getExtensionLength().getValue()) {
            LOGGER.debug("Parsing client KeyShareExtensionMessage");
            parseKeyShareListBytes(msg);
        } else {
            LOGGER.debug("Parsing client KeyShareExtensionMessage");
            msg.setKeyShareListLength(msg.getExtensionLength().getValue());
            LOGGER.debug("KeyShareListLength: " + msg.getExtensionLength().getValue());
            setPointer(getPointer() - ExtensionByteLength.KEY_SHARE_LIST_LENGTH);
            parseKeyShareListBytes(msg);
        }
        int position = 0;
        pairList = new LinkedList<>();
        while (position < msg.getKeyShareListLength().getValue()) {
            KeySharePairParser parser = new KeySharePairParser(position, msg.getKeyShareListBytes().getValue());
            pairList.add(parser.parse());
            if (position == parser.getPointer()) {
                throw new ParserException("Ran into infinite Loop while parsing KeySharePairs");
            }
            position = parser.getPointer();
        }
        parseKeyShareList(msg);
    }

    @Override
    protected KeyShareExtensionMessage createExtensionMessage() {
        return new KeyShareExtensionMessage();
    }

    /**
     * Reads the next bytes as the keySahreListLength of the Extension and
     * writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeySahreListLength(KeyShareExtensionMessage msg) {
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
        msg.setKeyShareList(pairList);
    }
}
