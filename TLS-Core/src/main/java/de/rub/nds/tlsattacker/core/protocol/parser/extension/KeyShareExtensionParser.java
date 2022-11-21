/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<KeyShareEntry> entryList;

    private boolean helloRetryRequestHint = false;

    public KeyShareExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(KeyShareExtensionMessage msg) {
        if (helloRetryRequestHint) {
            parseHRRKeyShare(msg);
        } else {
            parseRegularKeyShare(msg);
        }
        msg.setRetryRequestMode(helloRetryRequestHint);
    }

    @Override
    protected KeyShareExtensionMessage createExtensionMessage() {
        return new KeyShareExtensionMessage();
    }

    private void parseRegularKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as regular KeyShareExtension");
        parseKeyShareListLength(msg);
        if (msg.getKeyShareListLength().getValue() + ExtensionByteLength.KEY_SHARE_LIST_LENGTH
            == msg.getExtensionLength().getValue()) {
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

    private void parseHRRKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as HelloRetryRequest KeyShareExtension");
        msg.setKeyShareListBytes(parseByteArrayField(NamedGroup.LENGTH));
        entryList = new LinkedList<>();
        KeyShareEntryParser parser = new KeyShareEntryParser(0, msg.getKeyShareListBytes().getValue());
        entryList.add(parser.parse());
        parseKeyShareList(msg);
    }

    /**
     * Reads the next bytes as the keyShareListLength of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareListLength(KeyShareExtensionMessage msg) {
        msg.setKeyShareListLength(parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH));
        LOGGER.debug("KeyShareListLength: " + msg.getKeyShareListLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShareListBytes of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareListBytes(KeyShareExtensionMessage msg) {
        msg.setKeyShareListBytes(parseByteArrayField(msg.getKeyShareListLength().getValue()));
        LOGGER.debug("KeyShareListBytes: " + ArrayConverter.bytesToHexString(msg.getKeyShareListBytes().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareList of the Extension and writes them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareList(KeyShareExtensionMessage msg) {
        msg.setKeyShareList(entryList);
    }

    public boolean isHelloRetryRequestHint() {
        return helloRetryRequestHint;
    }

    public void setHelloRetryRequestHint(boolean helloRetryRequestHint) {
        this.helloRetryRequestHint = helloRetryRequestHint;
    }
}
