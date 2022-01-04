/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<KeyShareEntry> entryList;

    private boolean helloRetryRequestHint = false;

    public KeyShareExtensionParser(InputStream stream, Config config) {
        super(stream, config);
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

    private void parseRegularKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as regular KeyShareExtension");
        parseKeyShareListLength(msg);
        parseKeyShareListBytes(msg);

        ByteArrayInputStream innerStream = new ByteArrayInputStream(msg.getKeyShareListBytes().getValue());
        entryList = new LinkedList<>();
        while (innerStream.available() > 0) {
            KeyShareEntryParser parser = new KeyShareEntryParser(innerStream);
            KeyShareEntry entry = new KeyShareEntry();
            parser.parse(entry);
            entryList.add(entry);
        }
        parseKeyShareList(msg);
    }

    private void parseHRRKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as HelloRetryRequest KeyShareExtension");
        msg.setKeyShareListBytes(parseByteArrayField(NamedGroup.LENGTH));
        entryList = new LinkedList<>();
        KeyShareEntryParser parser =
                new KeyShareEntryParser(new ByteArrayInputStream(msg.getKeyShareListBytes().getValue()));
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);
        entryList.add(entry);
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
