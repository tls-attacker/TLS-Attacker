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
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskEcDhClientKeyExchangePreparator extends
        ECDHClientKeyExchangePreparator<PskEcDhClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private ByteArrayOutputStream outputStream;
    private final PskEcDhClientKeyExchangeMessage msg;

    public PskEcDhClientKeyExchangePreparator(Chooser chooser, PskEcDhClientKeyExchangeMessage message) {
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
    protected byte[] computePremasterSecret(EllipticCurve curve, Point publicKey, BigInteger privateKey) {
        byte[] premasterSecret = super.computePremasterSecret(curve, publicKey, privateKey);
        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(premasterSecret.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("PremasterSecret: dhValue Length: " + premasterSecret.length);
            outputStream.write(premasterSecret);
            LOGGER.debug("PremasterSecret: dhValue" + Arrays.toString(premasterSecret));
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PSK PremasterSecret: " + Arrays.toString(tempPremasterSecret));
        return tempPremasterSecret;
    }
}
