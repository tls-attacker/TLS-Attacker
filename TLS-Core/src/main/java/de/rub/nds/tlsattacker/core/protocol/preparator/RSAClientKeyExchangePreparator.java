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
import de.rub.nds.tlsattacker.core.constants.Bits;
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

public class RSAClientKeyExchangePreparator<T extends RSAClientKeyExchangeMessage>
    extends ClientKeyExchangePreparator<T> {

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
        msg.getComputations().setPremasterSecretProtocolVersion(chooser.getHighestClientProtocolVersion().getValue());
        byte[] premasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET - HandshakeByteLength.VERSION];
        chooser.getContext().getRandom().nextBytes(premasterSecret);
        return ArrayConverter.concatenate(msg.getComputations().getPremasterSecretProtocolVersion().getValue(),
            premasterSecret);
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
        msg.getComputations().setPlainPaddedPremasterSecret(ArrayConverter.concatenate(new byte[] { 0x00, 0x02 },
            padding, new byte[] { 0x00 }, msg.getComputations().getPremasterSecret().getValue()));
        LOGGER.debug("PlainPaddedPremasterSecret: "
            + ArrayConverter.bytesToHexString(msg.getComputations().getPlainPaddedPremasterSecret().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        clientServerRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(clientServerRandom);
        LOGGER.debug("ClientServerRandom: "
            + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    protected void prepareSerializedPublicKey(T msg) {
        msg.setPublicKey(encrypted);
        LOGGER.debug("SerializedPublicKey (encrypted premaster secret): "
            + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug(
            "SerializedPublicKeyLength (encrypted premaster secret length): " + msg.getPublicKeyLength().getValue());
    }

    public byte[] decryptPremasterSecret() {
        BigInteger bigIntegerEncryptedPremasterSecret = new BigInteger(1, msg.getPublicKey().getValue());
        BigInteger serverPrivateKey = chooser.getServerRSAPrivateKey();
        if (chooser.getServerRsaModulus().equals(BigInteger.ZERO)) {
            LOGGER.warn("RSA Modulus is Zero, returning new byte[0] as decryptedPremasterSecret");
            return new byte[0];
        }
        // Make sure that the private key is not negative
        BigInteger decrypted =
            bigIntegerEncryptedPremasterSecret.modPow(serverPrivateKey.abs(), chooser.getServerRsaModulus().abs());
        return decrypted.toByteArray();
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        int keyByteLength = chooser.getServerRsaModulus().bitLength() / Bits.IN_A_BYTE;
        // For RSA, the PublicKey field actually contains the encrypted
        // premaster secret
        if (clientMode && (msg.getPublicKey() == null || msg.getPublicKey().getValue() == null)) {
            int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
            // If the key is really really short it might be impossible to add
            // padding;
            if (randomByteLength > 0) {
                padding = new byte[randomByteLength];
                chooser.getContext().getRandom().nextBytes(padding);
                ArrayConverter.makeArrayNonZero(padding);
            } else {
                padding = new byte[0];
            }
            preparePadding(msg);
            premasterSecret = generatePremasterSecret();
            preparePremasterSecret(msg);
            preparePlainPaddedPremasterSecret(msg);

            byte[] paddedPremasterSecret = msg.getComputations().getPlainPaddedPremasterSecret().getValue();

            if (paddedPremasterSecret.length == 0) {
                LOGGER.warn("paddedPremasterSecret length is zero length!");
                paddedPremasterSecret = new byte[] { 0 };
            }
            BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
            BigInteger biEncrypted = biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey().abs(),
                chooser.getServerRsaModulus().abs());
            encrypted = ArrayConverter.bigIntegerToByteArray(biEncrypted,
                chooser.getServerRsaModulus().bitLength() / Bits.IN_A_BYTE, true);
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
                premasterSecret =
                    Arrays.copyOfRange(paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
                premasterSecret = manipulatePremasterSecret(premasterSecret);
                preparePremasterSecret(msg);
                if (premasterSecret.length > 2) {
                    msg.getComputations().setPremasterSecretProtocolVersion(Arrays.copyOfRange(premasterSecret, 0, 2));
                    LOGGER.debug("PMS Protocol Version {}",
                        msg.getComputations().getPremasterSecretProtocolVersion().getValue());
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
