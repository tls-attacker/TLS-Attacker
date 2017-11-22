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
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskServerKeyExchangePreparator extends ServerKeyExchangePreparator<PskServerKeyExchangeMessage> {

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
        prepareClientRandom(msg);
    }

    private void prepareClientRandom(PskServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }
}
