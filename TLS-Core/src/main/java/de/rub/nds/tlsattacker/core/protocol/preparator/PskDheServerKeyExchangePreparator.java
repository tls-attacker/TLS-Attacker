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
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskDheServerKeyExchangePreparator extends DHEServerKeyExchangePreparator<PskDheServerKeyExchangeMessage> {

    private final PskDheServerKeyExchangeMessage msg;

    public PskDheServerKeyExchangePreparator(Chooser chooser, PskDheServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        msg.setIdentityHint(chooser.getPSKIdentity());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        setComputedModulus(msg);
        setComputedGenerator(msg);
        setComputedPrivateKey(msg);
        BigInteger modulus = msg.getComputations().getModulus().getValue();
        BigInteger generator = msg.getComputations().getGenerator().getValue();
        BigInteger privateKey = msg.getComputations().getPrivateKey().getValue();

        // Compute PublicKeys
        prepareModulus(msg);
        prepareModulusLength(msg);
        prepareGenerator(msg);
        prepareGeneratorLength(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);
    }
}
