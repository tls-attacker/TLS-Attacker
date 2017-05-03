/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator.extension;

import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;

/**
 * @author Nurullah Erinola
 */
public class KeySharePairPreparator extends Preparator<KeySharePair> {

    private final KeySharePair pair;

    public KeySharePairPreparator(TlsContext context, KeySharePair pair) {
        super(context, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        pair.setKeyShare(pair.getKeyShareConfig());
        pair.setKeyShareType(pair.getKeyShareTypeConfig());
        pair.setKeyShareLength(pair.getKeyShare().getValue().length);
    }

}