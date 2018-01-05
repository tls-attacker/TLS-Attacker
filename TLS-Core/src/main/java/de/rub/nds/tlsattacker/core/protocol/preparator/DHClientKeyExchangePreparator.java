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
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.bouncycastle.util.BigIntegers;

public class DHClientKeyExchangePreparator<T extends DHClientKeyExchangeMessage> extends ClientKeyExchangePreparator<T> {

    protected BigInteger clientPublicKey;
    protected byte[] premasterSecret;
    protected byte[] random;
    protected byte[] masterSecret;
    protected final T msg;

    public DHClientKeyExchangePreparator(Chooser chooser, T msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing DHClientExchangeMessage");
        msg.prepareComputations();
        setDhParams();

        premasterSecret = calculatePremasterSecret(msg.getComputations().getModulus().getValue(), msg.getComputations()
                .getPrivateKey().getValue(), msg.getComputations().getServerPublicKey().getValue());
        clientPublicKey = calculatePublicKey(msg.getComputations().getGenerator().getValue(), msg.getComputations()
                .getModulus().getValue(), msg.getComputations().getPrivateKey().getValue());
        prepareDhParams();
    }

    protected void setDhParams() {
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg);
        setComputationServerPublicKey(msg);
    }

    protected void prepareDhParams() {
        preparePremasterSecret(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        prepareClientRandom(msg);
    }

    protected BigInteger calculatePublicKey(BigInteger generator, BigInteger modulus, BigInteger privateKey) {
        return generator.modPow(privateKey, modulus);
    }

    protected byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        if (modulus == BigInteger.ZERO) {
            LOGGER.warn("Modulus is ZERO. Returning empty premaster Secret");
            return new byte[0];
        }
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey, modulus));
    }

    protected void setComputationGenerator(T msg) {
        msg.getComputations().setGenerator(chooser.getServerDhGenerator());
        LOGGER.debug("Generator: " + msg.getComputations().getGenerator().getValue());
    }

    protected void setComputationModulus(T msg) {
        msg.getComputations().setModulus(chooser.getServerDhModulus());
        LOGGER.debug("Modulus: " + msg.getComputations().getModulus().getValue());
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void preparePublicKey(T msg) {
        msg.setPublicKey(clientPublicKey.toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void preparePublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void prepareClientRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(random);
        random = msg.getComputations().getClientRandom().getValue();
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        BigInteger privateKey = chooser.getDhServerPrivateKey();
        BigInteger clientPublic = new BigInteger(1, msg.getPublicKey().getValue());
        msg.prepareComputations();
        premasterSecret = calculatePremasterSecret(chooser.getServerDhModulus(), privateKey, clientPublic);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }

    protected void setComputationPrivateKey(T msg) {
        msg.getComputations().setPrivateKey(chooser.getDhClientPrivateKey());
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }

    protected void setComputationServerPublicKey(T msg) {
        msg.getComputations().setServerPublicKey(chooser.getDhServerPublicKey());
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getServerPublicKey().getValue().toString());
    }
}
