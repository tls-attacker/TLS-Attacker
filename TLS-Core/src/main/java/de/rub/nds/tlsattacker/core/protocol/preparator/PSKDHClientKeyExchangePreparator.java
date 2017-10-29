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
import de.rub.nds.tlsattacker.core.protocol.message.PSKDHClientKeyExchangeMessage;
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
public class PSKDHClientKeyExchangePreparator extends ClientKeyExchangePreparator<PSKDHClientKeyExchangeMessage> {

    private byte[] premasterSecret;
    private byte[] clientRandom;
    private final PSKDHClientKeyExchangeMessage msg;
    private ByteArrayOutputStream outputStream;
    private BigInteger clientPublicKey;
    private byte[] dhValue;

    public PSKDHClientKeyExchangePreparator(Chooser chooser, PSKDHClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getConfig().getDefaultPSKIdentity());
        msg.setIdentityLength(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKIdentity().length, 2));
        msg.prepareComputations();
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg);
        setComputationServerPublicKey(msg);

        clientPublicKey = calculatePublicKey(msg.getComputations().getGenerator().getValue(), msg.getComputations()
                .getModulus().getValue(), msg.getComputations().getPrivateKey().getValue());
        dhValue = calculatePremasterSecret(msg.getComputations().getModulus().getValue(), msg.getComputations()
                .getPrivateKey().getValue(), msg.getComputations().getServerPublicKey().getValue());
        premasterSecret = generatePremasterSecret(dhValue);
        preparePremasterSecret(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        prepareClientRandom(msg);
    }

    private byte[] generatePremasterSecret(byte[] dhValue) {

        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(dhValue.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("PremasterSecret: dhValue Length: " + dhValue.length);
            outputStream.write(dhValue);
            LOGGER.debug("PremasterSecret: dhValue" + dhValue);
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("TEST PremasterSecret: " + tempPremasterSecret);
        return tempPremasterSecret;
    }

    private byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey, modulus));
    }

    private void preparePremasterSecret(PSKDHClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareClientRandom(PSKDHClientKeyExchangeMessage msg) {
        // TODO spooky
        clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private BigInteger calculatePublicKey(BigInteger generator, BigInteger modulus, BigInteger privateKey) {
        return generator.modPow(privateKey, modulus);
    }

    private void preparePublicKey(PSKDHClientKeyExchangeMessage msg) {
        msg.setPublicKey(clientPublicKey.toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void preparePublicKeyLength(PSKDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    @Override
    public void prepareAfterParse() {
        BigInteger privateKey = chooser.getDhServerPrivateKey();
        BigInteger clientPublic = new BigInteger(1, msg.getPublicKey().getValue());
        msg.prepareComputations();
        dhValue = calculatePremasterSecret(chooser.getDhModulus(), privateKey, clientPublic);
        premasterSecret = generatePremasterSecret(dhValue);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    private void setComputationPrivateKey(PSKDHClientKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(chooser.getDhClientPrivateKey());
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }

    private void setComputationServerPublicKey(PSKDHClientKeyExchangeMessage msg) {
        msg.getComputations().setServerPublicKey(chooser.getDhServerPublicKey());
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getServerPublicKey().getValue().toString());
    }

    private void setComputationModulus(PSKDHClientKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getDhModulus());
        LOGGER.debug("Modulus: " + msg.getComputations().getModulus().getValue());
    }

    private void setComputationGenerator(PSKDHClientKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getDhGenerator());
        LOGGER.debug("Generator: " + msg.getComputations().getGenerator().getValue());
    }
}
