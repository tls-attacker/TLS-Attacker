/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class KeySharePairPreparator extends Preparator<KeySharePair> {

    private final KeySharePair pair;

    public KeySharePairPreparator(TlsContext context, KeySharePair pair) {
        super(context, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing ServerNamePairMessage");
        prepareKeyShare(pair);
        prepareKeyShareType(pair);
        prepareKeyShareLength(pair);
    }

    private void prepareKeyShare(KeySharePair pair) {
        pair.setKeyShare(pair.getKeyShareConfig());
        LOGGER.debug("KeyShare: " + ArrayConverter.bytesToHexString(pair.getKeyShare().getValue()));
    }

    private void prepareKeyShareType(KeySharePair pair) {
        pair.setKeyShareType(pair.getKeyShareTypeConfig());
        LOGGER.debug("KeyShareType: " + ArrayConverter.bytesToHexString(pair.getKeyShareType().getValue()));
    }

    private void prepareKeyShareLength(KeySharePair pair) {
        pair.setKeyShareLength(pair.getKeyShare().getValue().length);
        LOGGER.debug("KeyShareLength: " + pair.getKeyShareLength().getValue());
    }

}