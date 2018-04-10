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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeyShareEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

public class KeyShareEntryParser extends Parser<KeyShareEntry> {

    private KeyShareEntry entry;

    public KeyShareEntryParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public KeyShareEntry parse() {
        LOGGER.debug("Parsing KeyShareEntry");
        entry = new KeyShareEntry();
        parseKeyShareType(entry);
        if (getBytesLeft() > 0) {
            parseKeyShareLength(entry);
            parseKeyShare(entry);
        }
        return entry;
    }

    /**
     * Reads the next bytes as the keyShareType of the Extension and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareType(KeyShareEntry pair) {
        pair.setGroup(parseByteArrayField(ExtensionByteLength.KEY_SHARE_TYPE));
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(pair.getGroup().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareLength of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareLength(KeyShareEntry pair) {
        pair.setPublicKeyLength(parseIntField(ExtensionByteLength.KEY_SHARE_LENGTH));
        LOGGER.debug("KeyShareLength: " + pair.getPublicKeyLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShare of the Extension and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShare(KeyShareEntry pair) {
        pair.setPublicKey(parseByteArrayField(pair.getPublicKeyLength().getValue()));
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(pair.getPublicKey().getValue()));
    }
}
