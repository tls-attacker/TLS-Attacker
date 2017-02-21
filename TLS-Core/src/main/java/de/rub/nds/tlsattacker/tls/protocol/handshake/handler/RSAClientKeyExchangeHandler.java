/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handler;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateParsingException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.logging.Level;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class RSAClientKeyExchangeHandler extends ClientKeyExchangeHandler<RSAClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(RSAClientKeyExchangeHandler.class);
    private static RSAPublicKey bufferedKey = null;

    public RSAClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = RSAClientKeyExchangeMessage.class;
        this.keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA;
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
        RSAPublicKey publicKey = null;
        Certificate cert = tlsContext.getServerCertificate();
        X509CertificateObject certObject;
        try {
            certObject = new X509CertificateObject(cert.getCertificateAt(0));
        } catch (CertificateParsingException ex) {
            throw new WorkflowExecutionException("Could not parse server certificate", ex);
        }
        if (!certObject.getPublicKey().getAlgorithm().equals("RSA")) {

            if (tlsContext.getConfig().isFuzzingMode()) {
                if (bufferedKey == null) {
                    KeyPairGenerator keyGen = null;
                    try {
                        keyGen = KeyPairGenerator.getInstance("RSA", "BC");
                    } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                        LOGGER.error(ex.getLocalizedMessage(), ex);
                    }
                    bufferedKey = (RSAPublicKey) keyGen.genKeyPair().getPublic();
                }
                publicKey = bufferedKey;// TODO not multithreadable
            } else {
                throw new WorkflowExecutionException("Cannot use non-RSA public Key in RSA-ClientKeyExchangeHandler");
            }
        } else {
            publicKey = (RSAPublicKey) certObject.getPublicKey();

        }
        int keyByteLength = publicKey.getModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
        byte[] padding = new byte[randomByteLength];
        RandomHelper.getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);

        byte[] premasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];

        RandomHelper.getRandom().nextBytes(premasterSecret);
        premasterSecret[0] = tlsContext.getSelectedProtocolVersion().getMajor();
        premasterSecret[1] = tlsContext.getSelectedProtocolVersion().getMinor();
        protocolMessage.setPremasterSecret(premasterSecret);

        LOGGER.debug("Computed PreMaster Secret: {}",
                ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));

        protocolMessage.setPlainPaddedPremasterSecret(ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding,
                new byte[] { 0x00 }, protocolMessage.getPremasterSecret().getValue()));

        byte[] paddedPremasterSecret = protocolMessage.getPlainPaddedPremasterSecret().getValue();

        byte[] random = tlsContext.getClientServerRandom();

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getSelectedProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
                .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        protocolMessage.setMasterSecret(masterSecret);
        LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

        tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

        try {
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            LOGGER.debug("Encrypting the following padded premaster secret: {}",
                    ArrayConverter.bytesToHexString(paddedPremasterSecret));
            // TODO can throw a tooMuchData for RSA Block exception
            if (paddedPremasterSecret.length == 0) {
                paddedPremasterSecret = new byte[] { 0 };
            }
            if (new BigInteger(paddedPremasterSecret).compareTo(publicKey.getModulus()) == 1) {
                if (tlsContext.getConfig().isFuzzingMode()) {
                    paddedPremasterSecret = masterSecret;
                } else {
                    throw new IllegalStateException("Trying to encrypt more data then modulus size!");
                }
            }
            byte[] encrypted = null;
            try {
                encrypted = cipher.doFinal(paddedPremasterSecret);
            } catch (org.bouncycastle.crypto.DataLengthException | ArrayIndexOutOfBoundsException E) {
                // too much data for RSA block
                throw new UnsupportedOperationException(E);
            }
            protocolMessage.setEncryptedPremasterSecret(encrypted);
            protocolMessage
                    .setEncryptedPremasterSecretLength(protocolMessage.getEncryptedPremasterSecret().getValue().length);
            return ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
                    .getEncryptedPremasterSecretLength().getValue(),
                    HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH), protocolMessage
                    .getEncryptedPremasterSecret().getValue());
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchProviderException | InvalidKeyException
                | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            LOGGER.info(ex);
            throw new WorkflowExecutionException(ex.getLocalizedMessage());
        }

    }

    @Override
    int parseKeyExchangeMessage(byte[] message, int currentPointer) {
        int nextPointer = currentPointer + HandshakeByteLength.ENCRYPTED_PREMASTER_SECRET_LENGTH;
        int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setEncryptedPremasterSecretLength(length);
        currentPointer = nextPointer;

        nextPointer = currentPointer + length;
        protocolMessage.setEncryptedPremasterSecret(Arrays.copyOfRange(message, currentPointer, nextPointer));

        byte[] encryptedPremasterSecret = protocolMessage.getEncryptedPremasterSecret().getValue();

        KeyStore ks = tlsContext.getConfig().getKeyStore();

        try {
            Key key = ks.getKey(tlsContext.getConfig().getAlias(), tlsContext.getConfig().getPassword().toCharArray());
            RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;

            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, rsaKey);
            LOGGER.debug("Decrypting the following encrypted premaster secret: {}",
                    ArrayConverter.bytesToHexString(encryptedPremasterSecret));
            byte[] decrypted = cipher.doFinal(encryptedPremasterSecret);

            protocolMessage.setPlainPaddedPremasterSecret(decrypted);

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | InvalidKeyException
                | NoSuchProviderException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new ConfigurationException(
                    "Something went wrong loading key from Keystore or decrypting Premastersecret", ex);
        }

        byte[] plainPaddedPremasterSecret = protocolMessage.getPlainPaddedPremasterSecret().getValue();

        int plainPaddedPremasterSecretLength = plainPaddedPremasterSecret.length;

        int plainPaddedPremasterSecretoffset = plainPaddedPremasterSecretLength - 48;

        byte[] premasterSecret = Arrays.copyOfRange(plainPaddedPremasterSecret, plainPaddedPremasterSecretoffset,
                plainPaddedPremasterSecretLength);

        LOGGER.debug("Resulting premaster secret: {}", ArrayConverter.bytesToHexString(premasterSecret));

        protocolMessage.setPremasterSecret(premasterSecret);
        tlsContext.setPreMasterSecret(premasterSecret);

        byte[] random = tlsContext.getClientServerRandom();

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getSelectedProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
                .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        protocolMessage.setMasterSecret(masterSecret);
        LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

        tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

        currentPointer = nextPointer;

        return currentPointer;
    }
}
