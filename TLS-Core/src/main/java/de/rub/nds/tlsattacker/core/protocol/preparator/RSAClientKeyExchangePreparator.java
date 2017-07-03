/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RSAClientKeyExchangePreparator extends ClientKeyExchangePreparator<RSAClientKeyExchangeMessage> {

    private byte[] padding;
    private byte[] premasterSecret;
    private byte[] clientRandom;
    private byte[] masterSecret;
    private byte[] encrypted;
    private final RSAClientKeyExchangeMessage msg;

    public RSAClientKeyExchangePreparator(Chooser chooser, RSAClientKeyExchangeMessage message) {
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
        RandomHelper.getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);
        preparePadding(msg);
        premasterSecret = generatePremasterSecret();
        preparePremasterSecret(msg);
        // TODO what are those magic numbers?
        preparePlainPaddedPremasterSecret(msg);

        byte[] paddedPremasterSecret = msg.getComputations().getPlainPaddedPremasterSecret().getValue();

        prepareClientRandom(msg);

        if (paddedPremasterSecret.length == 0) {
            paddedPremasterSecret = new byte[] { 0 };
        }
        BigInteger biPaddedPremasterSecret = new BigInteger(paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(chooser.getServerRSAPublicKey(),
                chooser.getRsaModulus());
        encrypted = ArrayConverter.bigIntegerToByteArray(biEncrypted, chooser.getRsaModulus().bitLength() / 8, true);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
    }

    private byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
        RandomHelper.getRandom().nextBytes(tempPremasterSecret);
        tempPremasterSecret[0] = chooser.getSelectedProtocolVersion().getMajor();
        tempPremasterSecret[1] = chooser.getSelectedProtocolVersion().getMinor();
        return tempPremasterSecret;
    }

    private RSAPublicKey generateFreshKey() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException ex) {
            throw new PreparationException("Could not generate a new Key", ex);
        }
        return (RSAPublicKey) keyGen.genKeyPair().getPublic();

    }

    private void preparePadding(RSAClientKeyExchangeMessage msg) {
        msg.getComputations().setPadding(padding);
        LOGGER.debug("Padding: " + ArrayConverter.bytesToHexString(msg.getComputations().getPadding().getValue()));
    }

    private void preparePremasterSecret(RSAClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void preparePlainPaddedPremasterSecret(RSAClientKeyExchangeMessage msg) {
        msg.getComputations().setPlainPaddedPremasterSecret(
                ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding, new byte[] { 0x00 }, msg
                        .getComputations().getPremasterSecret().getValue()));
        LOGGER.debug("PlainPaddedPremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPlainPaddedPremasterSecret().getValue()));
    }

    private void prepareClientRandom(RSAClientKeyExchangeMessage msg) {
        // TODO spooky
        clientRandom = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareSerializedPublicKey(RSAClientKeyExchangeMessage msg) {
        msg.setPublicKey(encrypted);
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(RSAClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private byte[] decryptPremasterSecret() {
        BigInteger bigIntegerEncryptedPremasterSecret = new BigInteger(msg.getPublicKey().getValue());
        BigInteger serverPrivateKey = chooser.getConfig().getDefaultServerRSAPrivateKey();
        BigInteger decrypted = bigIntegerEncryptedPremasterSecret.modPow(serverPrivateKey, chooser.getRsaModulus());
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
        premasterSecret = Arrays.copyOfRange(paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
