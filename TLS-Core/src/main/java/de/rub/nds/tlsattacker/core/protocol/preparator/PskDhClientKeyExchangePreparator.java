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
import de.rub.nds.tlsattacker.core.protocol.message.PskDhClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskDhClientKeyExchangePreparator extends DHClientKeyExchangePreparator<PskDhClientKeyExchangeMessage> {

    private final PskDhClientKeyExchangeMessage msg;
    private ByteArrayOutputStream outputStream;
    private byte[] dhValue;

    public PskDhClientKeyExchangePreparator(Chooser chooser, PskDhClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
        super.prepareHandshakeMessageContents();
        premasterSecret = generatePremasterSecret(premasterSecret);
        preparePremasterSecret(msg);
    }

    private byte[] generatePremasterSecret(byte[] dhValue) {

        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(dhValue.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("PremasterSecret: dhValue Length: " + dhValue.length);
            outputStream.write(dhValue);
            LOGGER.debug("PremasterSecret: dhValue" + ArrayConverter.bytesToHexString(dhValue));
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PremasterSecret: " + ArrayConverter.bytesToHexString(tempPremasterSecret));
        return tempPremasterSecret;
    }

    @Override
    public void prepareAfterParse() {
        LOGGER.debug("------------------------------------------");
        BigInteger privateKey = chooser.getPSKServerPrivateKey();
        BigInteger clientPublic = new BigInteger(1, msg.getPublicKey().getValue());
        msg.prepareComputations();
        dhValue = calculatePremasterSecret(chooser.getPSKModulus(), privateKey, clientPublic);
        premasterSecret = generatePremasterSecret(dhValue);
        LOGGER.debug("------------------------------------------");
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    @Override
    protected void setComputationServerPublicKey(PskDhClientKeyExchangeMessage msg) {
        msg.getComputations().setServerPublicKey(chooser.getPSKServerPublicKey());
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getServerPublicKey().getValue().toString());
    }

    @Override
    protected void setComputationModulus(PskDhClientKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getPSKModulus());
        LOGGER.debug("Modulus: " + msg.getComputations().getModulus().getValue());
    }

    @Override
    protected void setComputationGenerator(PskDhClientKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getPSKGenerator());
        LOGGER.debug("Generator: " + msg.getComputations().getGenerator().getValue());
    }
}
