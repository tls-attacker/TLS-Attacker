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
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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

    public RSAClientKeyExchangePreparator(TlsContext context, RSAClientKeyExchangeMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        RSAPublicKey publicKey;
        if (context.getServerCertificatePublicKey() == null
                || !"RSA".equals(context.getServerCertificatePublicKey().getAlgorithm())) {
            publicKey = generateFreshKey();
        } else {
            publicKey = (RSAPublicKey) context.getServerCertificatePublicKey();
        }

        int keyByteLength = publicKey.getModulus().bitLength() / 8;
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
        if (biPaddedPremasterSecret.compareTo(publicKey.getModulus()) == 1) {
            throw new PreparationException("Trying to encrypt more Data than moduls Size!");
        }
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        encrypted = ArrayConverter.bigIntegerToByteArray(biEncrypted, publicKey.getModulus().bitLength() / 8, true);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
    }

    private byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
        RandomHelper.getRandom().nextBytes(tempPremasterSecret);
        tempPremasterSecret[0] = context.getSelectedProtocolVersion().getMajor();
        tempPremasterSecret[1] = context.getSelectedProtocolVersion().getMinor();
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
        clientRandom = context.getClientServerRandom();
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareSerializedPublicKey(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(encrypted);
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private byte[] decryptPremasterSecret() {
        try {
            byte[] encryptedPremasterSecret = msg.getSerializedPublicKey().getValue();
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) context.getConfig().getPrivateKey();
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, rsaKey);
            return cipher.doFinal(encryptedPremasterSecret);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchProviderException
                | NoSuchPaddingException | InvalidKeyException ex) {
            throw new PreparationException("Could not decrypt PremasterSecret");
        }
    }

    @Override
    public void prepareAfterParse() {
        // Decrypt premaster secret
        msg.prepareComputations();
        byte[] paddedPremasterSecret = decryptPremasterSecret();
        System.out.println("PaddedPremaster:" + ArrayConverter.bytesToHexString(paddedPremasterSecret));
        RSAPublicKey key = null;
        try {
            key = (RSAPublicKey) context.getConfig().getPublicKey();
        } catch (CertificateParsingException E) {
            throw new PreparationException("Could not retrieve publicKey from config");
        }
        int keyByteLength = key.getModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 1;
        premasterSecret = Arrays.copyOfRange(paddedPremasterSecret, randomByteLength, paddedPremasterSecret.length);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
