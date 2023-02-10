/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.PskDheServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDheServerKeyExchangePreparator extends DHEServerKeyExchangePreparator<PskDheServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskDheServerKeyExchangeMessage msg;

    public PskDheServerKeyExchangePreparator(Chooser chooser, PskDheServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentityHint(chooser.getPSKIdentityHint());
        msg.setIdentityHintLength(msg.getIdentityHint().getValue().length);
        setPskDheParams();
        preparePskPublicKey(msg);
        super.prepareDheParams();
    }

    private void setPskDheParams() {
        msg.prepareKeyExchangeComputations();
        setComputedPskDhGenerator(msg);
        setComputedPskDhModulus(msg);
        setComputedPskDhPrivateKey(msg);
    }

    protected void setComputedPskDhPrivateKey(PskDheServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setPrivateKey(chooser.getPSKServerPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getKeyExchangeComputations().getPrivateKey().getValue());
    }

    protected void setComputedPskDhModulus(PskDheServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setModulus(chooser.getPSKModulus());
        LOGGER.debug("Modulus used for Computations: " + msg.getKeyExchangeComputations().getModulus().getValue().toString(16));
    }

    protected void setComputedPskDhGenerator(PskDheServerKeyExchangeMessage msg) {
        msg.getKeyExchangeComputations().setGenerator(chooser.getPSKGenerator());
        LOGGER
            .debug("Generator used for Computations: " + msg.getKeyExchangeComputations().getGenerator().getValue().toString(16));
    }

    private void preparePskPublicKey(PskDheServerKeyExchangeMessage msg) {
        msg.setPublicKey(chooser.getPSKServerPublicKey().toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

}
