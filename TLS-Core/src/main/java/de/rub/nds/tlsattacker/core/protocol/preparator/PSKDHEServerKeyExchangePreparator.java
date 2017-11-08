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
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHEServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PSKDHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<PSKDHEServerKeyExchangeMessage> {

    private final PSKDHEServerKeyExchangeMessage msg;

    public PSKDHEServerKeyExchangePreparator(Chooser chooser, PSKDHEServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        if (chooser.getConfig().getDefaultPSKIdentityHint() != null) {
            msg.setIdentityHint(chooser.getConfig().getDefaultPSKIdentityHint());
        }
        if (chooser.getConfig().getDefaultPSKIdentityHint() != null) {
            msg.setIdentityHintLength(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKIdentityHint().length,
                    HandshakeByteLength.PSK_IDENTITY_LENGTH));
        } else {
            msg.setIdentityHintLength(ArrayConverter.intToBytes(HandshakeByteLength.PSK_ZERO,
                    HandshakeByteLength.PSK_IDENTITY_LENGTH));
        }
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

    private void prepareGenerator(PSKDHEServerKeyExchangeMessage msg) {
        msg.setGenerator(msg.getComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    private void prepareModulus(PSKDHEServerKeyExchangeMessage msg) {
        msg.setModulus(msg.getComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    private void prepareGeneratorLength(PSKDHEServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: " + msg.getGeneratorLength().getValue());
    }

    private void prepareModulusLength(PSKDHEServerKeyExchangeMessage msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    private void preparePublicKey(PSKDHEServerKeyExchangeMessage msg) {
        msg.setPublicKey(chooser.getDhServerPublicKey().toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void preparePublicKeyLength(PSKDHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void setComputedPrivateKey(PSKDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(chooser.getDhServerPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue());
    }

    private void setComputedModulus(PSKDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getDhModulus());
        LOGGER.debug("Modulus used for Computations: " + msg.getComputations().getModulus().getValue().toString(16));
    }

    private void setComputedGenerator(PSKDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getDhGenerator());
        LOGGER.debug("Generator used for Computations: " + msg.getComputations().getGenerator().getValue().toString(16));
    }

    private void prepareClientRandom(PSKDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(PSKDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(chooser.getServerRandom());
        LOGGER.debug("ServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getServerRandom().getValue()));
    }
}
