/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class PskDheServerKeyExchangePreparator
        extends DHEServerKeyExchangePreparator<PskDheServerKeyExchangeMessage> {

    private final PskDheServerKeyExchangeMessage msg;

    public PskDheServerKeyExchangePreparator(
            Chooser chooser, PskDheServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentityHint(chooser.getPSKIdentityHint());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        setPskDheParams();
        preparePublicKey(msg);
        super.prepareDheParams();
    }

    private void setPskDheParams() {
        msg.prepareKeyExchangeComputations();
        setComputedGenerator(msg);
        setComputedModulus(msg);
        setComputedPrivateKey(msg);
    }
}
