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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**

 */
public class KeySharePairSerializer extends Serializer<KeySharePair> {

    private final KeySharePair pair;

    public KeySharePairSerializer(KeySharePair pair) {
        this.pair = pair;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing KeySharePair");
        writeKeyShareType(pair);
        writeKeyShareLength(pair);
        writeKeyShare(pair);
        return getAlreadySerialized();
    }

    private void writeKeyShareType(KeySharePair pair) {
        appendBytes(pair.getKeyShareType().getValue());
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
    }

    private void writeKeyShareLength(KeySharePair pair) {
        appendInt(pair.getKeyShareLength().getValue(), ExtensionByteLength.KEY_SHARE_LENGTH);
        LOGGER.debug("KeyShareLength: " + pair.getKeyShareLength().getValue());
    }

    private void writeKeyShare(KeySharePair pair) {
        appendBytes(pair.getKeyShare().getValue());
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(pair.getKeyShare().getValue()));
    }

}
