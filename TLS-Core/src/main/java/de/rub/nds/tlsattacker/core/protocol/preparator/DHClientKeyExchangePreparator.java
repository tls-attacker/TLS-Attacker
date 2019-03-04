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
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

public class DHClientKeyExchangePreparator<T extends DHClientKeyExchangeMessage> extends ClientKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

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
        prepareAfterParse(true);
        prepareDhParams();
    }

    protected void setDhParams(boolean clientMode) {
        setComputationPrivateKey(msg, clientMode);
        setComputationPublicKey(msg, clientMode);
    }

    protected void prepareDhParams() {
        preparePremasterSecret(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        prepareClientServerRandom(msg);
    }

    protected BigInteger calculatePublicKey(BigInteger generator, BigInteger modulus, BigInteger privateKey) {
        if (modulus.compareTo(BigInteger.ZERO) == 0) {
            LOGGER.warn("Modulus is ZERO. Returning 0 publicKey");
            return BigInteger.ZERO;
        }
        return generator.modPow(privateKey.abs(), modulus.abs());
    }

    protected byte[] calculatePremasterSecret(BigInteger modulus, BigInteger privateKey, BigInteger publicKey) {
        if (modulus.compareTo(BigInteger.ZERO) == 0) {
            LOGGER.warn("Modulus is ZERO. Returning empty premaster Secret");
            return new byte[0];
        }
        return BigIntegers.asUnsignedByteArray(publicKey.modPow(privateKey.abs(), modulus.abs()));
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
        msg.setPublicKey(ArrayConverter.bigIntegerToByteArray(clientPublicKey));
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void preparePublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        random = msg.getComputations().getClientServerRandom().getValue();
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        setComputationGenerator(msg);
        setComputationModulus(msg);
        setComputationPrivateKey(msg, clientMode);
        if (clientMode) {
            clientPublicKey = calculatePublicKey(msg.getComputations().getGenerator().getValue(), msg.getComputations()
                    .getModulus().getValue(), msg.getComputations().getPrivateKey().getValue());
            preparePublicKey(msg);
        }
        setComputationPublicKey(msg, clientMode);
        premasterSecret = calculatePremasterSecret(msg.getComputations().getModulus().getValue(), msg.getComputations()
                .getPrivateKey().getValue(), msg.getComputations().getPublicKey().getValue());
        preparePremasterSecret(msg);

    }

    protected void setComputationPrivateKey(T msg, boolean clientMode) {
        if (clientMode) {
            msg.getComputations().setPrivateKey(chooser.getDhClientPrivateKey());
        } else {
            msg.getComputations().setPrivateKey(chooser.getDhServerPrivateKey());
        }
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }

    protected void setComputationPublicKey(T msg, boolean clientMode) {
        if (clientMode) {
            msg.getComputations().setPublicKey(chooser.getDhServerPublicKey());
        } else {
            msg.getComputations().setPublicKey(new BigInteger(1, msg.getPublicKey().getValue()));
        }
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getPublicKey().getValue().toString());
    }
}
