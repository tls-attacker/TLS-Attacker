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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PSKServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKServerKeyExchangePreparator extends ServerKeyExchangePreparator<PSKServerKeyExchangeMessage> {

    private final PSKServerKeyExchangeMessage msg;

    public PSKServerKeyExchangePreparator(Chooser chooser, PSKServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        msg.setIdentityHint(chooser.getConfig().getDefaultPSKIdentityHint());
        msg.setIdentityHintLength(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKIdentityHint().length,
                HandshakeByteLength.PSK_IDENTITY_LENGTH));
        msg.prepareComputations();
        prepareClientRandom(msg);
    }

    private void prepareClientRandom(PSKServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }
}
