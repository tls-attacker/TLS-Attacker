/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

/**
 * @author Nurullah Erinola
 */
public class KeySharePairSerializer extends Serializer<KeySharePair> {

    private final KeySharePair pair;

    public KeySharePairSerializer(KeySharePair pair) {
        this.pair = pair;
    }

    @Override
    protected byte[] serializeBytes() {
        appendBytes(pair.getKeyShareType().getValue());
        appendInt(pair.getKeyShareLength().getValue(), ExtensionByteLength.KEY_SAHRE_LENGTH);
        appendBytes(pair.getKeyShare().getValue());
        return getAlreadySerialized();
    }

}
