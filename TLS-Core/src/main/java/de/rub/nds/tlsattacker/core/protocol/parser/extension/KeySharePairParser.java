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
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.parser.Parser;

/**

 */
public class KeySharePairParser extends Parser<KeySharePair> {

    private KeySharePair pair;

    public KeySharePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public KeySharePair parse() {
        LOGGER.debug("Parsing KeySharePair");
        pair = new KeySharePair();
        parseKeyShareType(pair);
        parseKeyShareLength(pair);
        parseKeyShare(pair);
        return pair;
    }

    /**
     * Reads the next bytes as the keyShareType of the Extension and writes them
     * in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareType(KeySharePair pair) {
        pair.setKeyShareType(parseByteArrayField(ExtensionByteLength.KEY_SHARE_TYPE));
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
    }

    /**
     * Reads the next bytes as the keyShareLength of the Extension and writes
     * them in the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShareLength(KeySharePair pair) {
        pair.setKeyShareLength(parseIntField(ExtensionByteLength.KEY_SHARE_LENGTH));
        LOGGER.debug("ServerNameLength: " + pair.getKeyShareLength().getValue());
    }

    /**
     * Reads the next bytes as the keyShare of the Extension and writes them in
     * the message
     *
     * @param msg
     *            Message to write in
     */
    private void parseKeyShare(KeySharePair pair) {
        pair.setKeyShare(parseByteArrayField(pair.getKeyShareLength().getValue()));
        LOGGER.debug("ServerName: " + ArrayConverter.bytesToHexString(pair.getKeyShare().getValue()));
    }

}
