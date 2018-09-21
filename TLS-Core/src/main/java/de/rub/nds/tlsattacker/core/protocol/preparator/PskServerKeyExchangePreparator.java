/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.PskServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskServerKeyExchangePreparator extends ServerKeyExchangePreparator<PskServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskServerKeyExchangeMessage msg;

    public PskServerKeyExchangePreparator(Chooser chooser, PskServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        msg.setIdentityHint(chooser.getPSKIdentityHint());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        msg.prepareComputations();
        prepareClientServerRandom(msg);
    }

    private void prepareClientServerRandom(PskServerKeyExchangeMessage msg) {
        msg.getComputations().setClientServerRandom(chooser.getClientRandom());
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }
}
