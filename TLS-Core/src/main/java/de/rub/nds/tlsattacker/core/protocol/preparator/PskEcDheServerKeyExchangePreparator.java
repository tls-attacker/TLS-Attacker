/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.PskEcDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class PskEcDheServerKeyExchangePreparator extends
        ECDHEServerKeyExchangePreparator<PskEcDheServerKeyExchangeMessage> {

    private ECPublicKeyParameters pubEcParams;
    private ECPrivateKeyParameters privEcParams;
    private final PskEcDheServerKeyExchangeMessage msg;

    public PskEcDheServerKeyExchangePreparator(Chooser chooser, PskEcDheServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentityHint(chooser.getPSKIdentityHint());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        super.setEcDhParams();
        super.prepareEcDhParams();
    }
}
