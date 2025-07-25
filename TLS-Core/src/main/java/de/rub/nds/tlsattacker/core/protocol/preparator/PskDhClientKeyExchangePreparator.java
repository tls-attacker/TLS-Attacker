/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskDhClientKeyExchangePreparator
        extends DHClientKeyExchangePreparator<PskDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PskDhClientKeyExchangeMessage msg;
    private SilentByteArrayOutputStream outputStream;

    public PskDhClientKeyExchangePreparator(
            Chooser chooser, PskDhClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        super.prepareHandshakeMessageContents();
    }

    @Override
    protected byte[] calculatePremasterSecret(
            BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        byte[] otherSecret = super.calculatePremasterSecret(modulus, privateKey, publicKey);
        outputStream = new SilentByteArrayOutputStream();
        outputStream.write(
                DataConverter.intToBytes(otherSecret.length, HandshakeByteLength.PSK_LENGTH));
        LOGGER.debug("OtherSecret Length: {}", otherSecret.length);
        outputStream.write(otherSecret);
        LOGGER.debug("OtherSecret: {}", otherSecret);
        outputStream.write(
                DataConverter.intToBytes(
                        chooser.getConfig().getDefaultPSKKey().length,
                        HandshakeByteLength.PSK_LENGTH));
        outputStream.write(chooser.getConfig().getDefaultPSKKey());
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PSK PremasterSecret: {}", tempPremasterSecret);
        return tempPremasterSecret;
    }

    @Override
    public void prepareAfterParse() {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg);
        setComputationPublicKey(msg);
        premasterSecret =
                calculatePremasterSecret(
                        msg.getComputations().getModulus().getValue(),
                        msg.getComputations().getPrivateKey().getValue(),
                        msg.getComputations().getPublicKey().getValue());
        preparePremasterSecret(msg);
    }
}
