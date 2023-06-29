/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<KeyShareEntry> entryList;

    private boolean helloRetryRequestHint = false;

    private final ConnectionEndType talkingConnectionEndType;

    public KeyShareExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
        talkingConnectionEndType = tlsContext.getTalkingConnectionEndType();
    }

    @Override
    public void parse(KeyShareExtensionMessage msg) {
        if (helloRetryRequestHint) {
            parseHRRKeyShare(msg);
        } else {
            parseRegularKeyShare(msg);
        }
        msg.setRetryRequestMode(helloRetryRequestHint);
    }

    private void parseRegularKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as regular KeyShareExtension");
        entryList = new LinkedList<>();
        if (talkingConnectionEndType == ConnectionEndType.CLIENT) {
            parseKeyShareListLength(msg);
            parseKeyShareListBytes(msg);
            ByteArrayInputStream innerStream =
                    new ByteArrayInputStream(msg.getKeyShareListBytes().getValue());
            while (innerStream.available() > 0) {
                KeyShareEntry entry = parseKeyShareEntry(innerStream);
                entryList.add(entry);
            }
        } else {
            byte[] keyShareBytes = parseByteArrayField(getBytesLeft());
            msg.setKeyShareListBytes(keyShareBytes);
            entryList.add(parseKeyShareEntry(new ByteArrayInputStream(keyShareBytes)));
        }

        setKeyShareList(msg);
    }

    private KeyShareEntry parseKeyShareEntry(ByteArrayInputStream innerStream) {
        KeyShareEntryParser parser = new KeyShareEntryParser(innerStream, helloRetryRequestHint);
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);
        return entry;
    }

    private void parseHRRKeyShare(KeyShareExtensionMessage msg) {
        LOGGER.debug("Parsing KeyShareExtensionMessage as HelloRetryRequest KeyShareExtension");
        msg.setKeyShareListBytes(parseByteArrayField(NamedGroup.LENGTH));
        entryList = new LinkedList<>();
        KeyShareEntry entry =
                parseKeyShareEntry(new ByteArrayInputStream(msg.getKeyShareListBytes().getValue()));
        entryList.add(entry);
        setKeyShareList(msg);
    }

    /**
     * Reads the next bytes as the keyShareListLength of the Extension and writes them in the
     * message
     *
     * @param msg Message to write in
     */
    private void parseKeyShareListLength(KeyShareExtensionMessage msg) {
        msg.setKeyShareListLength(parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH));
        LOGGER.debug("KeyShareListLength: " + msg.getKeyShareListLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShareListBytes of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void parseKeyShareListBytes(KeyShareExtensionMessage msg) {
        msg.setKeyShareListBytes(parseByteArrayField(msg.getKeyShareListLength().getValue()));
        LOGGER.debug("KeyShareListBytes: {}", msg.getKeyShareListBytes().getValue());
    }

    /**
     * Reads the next bytes as the keyShareList of the Extension and writes them in the message
     *
     * @param msg Message to write in
     */
    private void setKeyShareList(KeyShareExtensionMessage msg) {
        msg.setKeyShareList(entryList);
    }

    public boolean isHelloRetryRequestHint() {
        return helloRetryRequestHint;
    }

    public void setHelloRetryRequestHint(boolean helloRetryRequestHint) {
        this.helloRetryRequestHint = helloRetryRequestHint;
    }
}
