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
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAClientKeyExchangePreparator<T extends RSAClientKeyExchangeMessage> extends
        ClientKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected byte[] padding;
    protected byte[] premasterSecret;
    protected byte[] clientServerRandom;
    protected byte[] masterSecret;
    protected byte[] encrypted;
    protected final T msg;

    public RSAClientKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        LOGGER.debug("Preparing RSAClientKeyExchangeMessage");
        prepareAfterParse(true);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
    }

    protected byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = chooser.getContext().getPreMasterSecret();
        if (tempPremasterSecret != null) {
            LOGGER.debug("Using preset PreMasterSecret from context.");
            return tempPremasterSecret;
        }
        msg.getComputations().setPremasterSecretProtocolVersion(chooser.getHighestClientProtocolVersion().getValue());
        if (msg.getComputations().getPremasterSecretProtocolVersion().getValue().length > HandshakeByteLength.PREMASTER_SECRET) {
            return msg.getComputations().getPlainPaddedPremasterSecret().getValue();
        } else {
            tempPremasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET
                    - msg.getComputations().getPremasterSecretProtocolVersion().getValue().length];
            chooser.getContext().getRandom().nextBytes(tempPremasterSecret);
            return ArrayConverter.concatenate(msg.getComputations().getPremasterSecretProtocolVersion().getValue(),
                    tempPremasterSecret);
        }
    }

    protected RSAPublicKey generateFreshKey() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            throw new PreparationException("Could not generate a new Key", ex);
        }
        return (RSAPublicKey) keyGen.genKeyPair().getPublic();

    }

    protected void preparePadding(T msg) {
        msg.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getComputations().getPadding().getValue()));
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void preparePlainPaddedPremasterSecret(T msg) {
        msg.getComputations().setPlainPaddedPremasterSecret(
                ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding, new byte[] { 0x00 }, msg
                        .getComputations().getPremasterSecret().getValue()));
        LOGGER.debug("PlainPaddedPremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPlainPaddedPremasterSecret().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        clientServerRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientServerRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    protected void prepareSerializedPublicKey(T msg) {
        msg.setPublicKey(encrypted);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected byte[] decryptPremasterSecret() {
        BigInteger bigIntegerEncryptedPremasterSecret = new BigInteger(1, msg.getPublicKey().getValue());
        BigInteger serverPrivateKey = chooser.getServerRSAPrivateKey();
        if (chooser.getServerRsaModulus().equals(BigInteger.ZERO)) {
            LOGGER.warn("RSA Modulus is Zero, returning new byte[0] as decryptedPremasterSecret");
            return new byte[0];
        }
        BigInteger decrypted = bigIntegerEncryptedPremasterSecret.modPow(serverPrivateKey, chooser
                .getServerRsaModulus().abs());
        return decrypted.toByteArray();
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        int keyByteLength = chooser.getServerRsaModulus().bitLength() / 8;
        if (clientMode && (msg.getPublicKey() == null || msg.getPublicKey().getValue() == null)) {
            int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
            padding = new byte[randomByteLength];
            chooser.getContext().getRandom().nextBytes(padding);
            ArrayConverter.makeArrayNonZero(padding);
            preparePadding(msg);
            premasterSecret = generatePremasterSecret();
            preparePremasterSecret(msg);
            preparePlainPaddedPremasterSecret(msg);

            byte[] paddedPremasterSecret = msg.getComputations().getPlainPaddedPremasterSecret().getValue();

            if (paddedPremasterSecret.length == 0) {
                LOGGER.warn("paddedPremasterSecret length is zero!");
                paddedPremasterSecret = new byte[] { 0 };
            }
            BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
            BigInteger biEncrypted = biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey(),
                    chooser.getServerRsaModulus());
            encrypted = ArrayConverter.bigIntegerToByteArray(biEncrypted,
                    chooser.getServerRsaModulus().bitLength() / 8, true);
            prepareSerializedPublicKey(msg);
            premasterSecret = manipulatePremasterSecret(premasterSecret);
            preparePremasterSecret(msg);
        } else {
            LOGGER.debug("Decrypting premasterSecret");
            int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
            // decrypt premasterSecret
            byte[] paddedPremasterSecret = decryptPremasterSecret();
            LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));
            if (randomByteLength < paddedPremasterSecret.length && randomByteLength > 0) {
                premasterSecret = Arrays.copyOfRange(paddedPremasterSecret, randomByteLength,
                        paddedPremasterSecret.length);
                premasterSecret = manipulatePremasterSecret(premasterSecret);
                preparePremasterSecret(msg);
                if (premasterSecret.length > 2) {
                    msg.getComputations().setPremasterSecretProtocolVersion(Arrays.copyOfRange(premasterSecret, 0, 2));
                } else {
                    LOGGER.warn("Decrypted PMS is not long enough to contain protocol version bytes");
                }
            } else {
                LOGGER.warn("RandomByteLength too short! Using empty premasterSecret!");
                premasterSecret = new byte[0];
            }
        }
    }

    protected byte[] manipulatePremasterSecret(byte[] premasterSecret) {
        return premasterSecret; // Nothing to do here
    }
}
