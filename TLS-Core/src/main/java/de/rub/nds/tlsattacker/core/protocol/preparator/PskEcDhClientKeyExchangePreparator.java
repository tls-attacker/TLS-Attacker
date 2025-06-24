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
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskEcDhClientKeyExchangePreparator
        extends ECDHClientKeyExchangePreparator<PskEcDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SilentByteArrayOutputStream outputStream;
    private final PskEcDhClientKeyExchangeMessage msg;

    public PskEcDhClientKeyExchangePreparator(
            Chooser chooser, PskEcDhClientKeyExchangeMessage message) {
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
    protected byte[] computePremasterSecret(
            EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        byte[] premasterSecret = super.computePremasterSecret(curve, publicKey, privateKey);
        outputStream = new SilentByteArrayOutputStream();
        outputStream.write(
                DataConverter.intToBytes(premasterSecret.length, HandshakeByteLength.PSK_LENGTH));
        LOGGER.debug("PremasterSecret: dhValue Length: {}", premasterSecret.length);
        outputStream.write(premasterSecret);
        LOGGER.debug("PremasterSecret: dhValue {}", premasterSecret);
        outputStream.write(
                DataConverter.intToBytes(
                        chooser.getConfig().getDefaultPSKKey().length,
                        HandshakeByteLength.PSK_LENGTH));
        outputStream.write(chooser.getConfig().getDefaultPSKKey());
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PSK PremasterSecret: {}", tempPremasterSecret);
        return tempPremasterSecret;
    }
}
