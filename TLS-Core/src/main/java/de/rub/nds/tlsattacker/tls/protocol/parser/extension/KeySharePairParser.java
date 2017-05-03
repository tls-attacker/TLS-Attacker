/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.parser.Parser;

/**
 * @author Nurullah Erinola
 */
public class KeySharePairParser extends Parser<KeySharePair> {

    public KeySharePairParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public KeySharePair parse() {
        KeySharePair pair = new KeySharePair();
        pair.setKeyShareType(parseByteArrayField(ExtensionByteLength.KEY_SHARE_TYPE));
        pair.setKeyShareLength(parseIntField(ExtensionByteLength.KEY_SAHRE_LENGTH));
        pair.setKeyShare(parseByteArrayField(pair.getKeyShareLength().getValue()));
        return pair;
    }

}
