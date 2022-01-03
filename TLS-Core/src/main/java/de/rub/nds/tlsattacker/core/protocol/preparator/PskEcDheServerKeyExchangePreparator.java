/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class PskEcDheServerKeyExchangePreparator
    extends ECDHEServerKeyExchangePreparator<PskEcDheServerKeyExchangeMessage> {

    private final PskEcDheServerKeyExchangeMessage msg;

    public PskEcDheServerKeyExchangePreparator(Chooser chooser, PskEcDheServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentityHint(chooser.getPSKIdentityHint());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        super.prepareHandshakeMessageContents();
    }
}
