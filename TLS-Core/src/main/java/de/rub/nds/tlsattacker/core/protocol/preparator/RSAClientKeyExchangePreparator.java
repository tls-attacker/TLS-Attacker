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

public class RSAClientKeyExchangePreparator<T extends RSAClientKeyExchangeMessage> extends
        ClientKeyExchangePreparator<T> {

    protected byte[] padding;
    protected byte[] premasterSecret;
    protected byte[] clientRandom;
    protected byte[] masterSecret;
    protected byte[] encrypted;
    protected final T msg;

    public RSAClientKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();

        int keyByteLength = chooser.getRsaModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
        padding = new byte[randomByteLength];
        chooser.getContext().getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);
        preparePadding(msg);
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
        preparePlainPaddedPremasterSecret(msg);

        byte[] paddedPremasterSecret = msg.getComputations().getPlainPaddedPremasterSecret().getValue();

        prepareClientRandom(msg);

        if (paddedPremasterSecret.length == 0) {
            paddedPremasterSecret = new byte[]{0};
        }
        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey(),
                chooser.getRsaModulus());
        encrypted = ArrayConverter.bigIntegerToByteArray(biEncrypted, chooser.getRsaModulus().bitLength() / 8, true);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
    }

    protected byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
        chooser.getContext().getRandom().nextBytes(tempPremasterSecret);
        tempPremasterSecret[0] = chooser.getSelectedProtocolVersion().getMajor();
        tempPremasterSecret[1] = chooser.getSelectedProtocolVersion().getMinor();
        return tempPremasterSecret;
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
                ArrayConverter.concatenate(new byte[]{0x00, 0x02}, padding, new byte[]{0x00}, msg
                .getComputations().getPremasterSecret().getValue()));
        LOGGER.debug("PlainPaddedPremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPlainPaddedPremasterSecret().getValue()));
    }

    protected void prepareClientRandom(T msg) {
        // TODO spooky
        clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
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
        BigInteger serverPrivateKey = chooser.getConfig().getDefaultServerRSAPrivateKey();
        if (chooser.getRsaModulus().equals(BigInteger.ZERO)) {
            LOGGER.warn("RSA Modulus is Zero, returning new byte[0] as decryptedPremasterSecret");
            return new byte[0];
        }
        BigInteger decrypted = bigIntegerEncryptedPremasterSecret.modPow(serverPrivateKey, chooser.getRsaModulus().abs());
        return decrypted.toByteArray();
    }

    @Override
    public void prepareAfterParse() {
        // Decrypt premaster secret
        msg.prepareComputations();
        byte[] paddedPremasterSecret = decryptPremasterSecret();
        LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));

        int keyByteLength = chooser.getRsaModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
        LOGGER.debug("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));
        if (randomByteLength < paddedPremasterSecret.length) {
            premasterSecret = Arrays.copyOfRange(paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
        } else {
            LOGGER.warn("RandomByteLength too short! Using empty premasterSecret!");
            premasterSecret = new byte[0];

        }
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
