/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        if (context.getServerPublicKey() == null || !"RSA".equals(context.getServerPublicKey().getAlgorithm())) {
            publicKey = generateFreshKey();
        } else {
            publicKey = (RSAPublicKey) context.getServerPublicKey();
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

        clientRandom = context.getClientServerRandom();
        prepareClientRandom(msg);

        masterSecret = generateMasterSecret();
        prepareMasterSecret(msg);
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            if (paddedPremasterSecret.length == 0) {
                paddedPremasterSecret = new byte[] { 0 };
            }
            if (new BigInteger(paddedPremasterSecret).compareTo(publicKey.getModulus()) == 1) {
                throw new PreparationException("Trying to encrypt more Data than moduls Size!");
            }
            encrypted = null;
            try {
                encrypted = cipher.doFinal(paddedPremasterSecret);
            } catch (org.bouncycastle.crypto.DataLengthException | ArrayIndexOutOfBoundsException E) {
                // too much data for RSA block
                throw new PreparationException("Too much data for RSA-Block", E);
            }
            prepareSerializedPublicKey(msg);
            prepareSerializedPublicKeyLength(msg);
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchProviderException | InvalidKeyException
                | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new PreparationException("Could not prepare RSAClientKeyExchange Message");
        }

    }

    private byte[] generatePremasterSecret() {
        byte[] tempPremasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
        RandomHelper.getRandom().nextBytes(tempPremasterSecret);
        tempPremasterSecret[0] = context.getSelectedProtocolVersion().getMajor();
        tempPremasterSecret[1] = context.getSelectedProtocolVersion().getMinor();
        return tempPremasterSecret;
    }

    private byte[] generateMasterSecret() {
        if (context.getSelectedCipherSuite() == null) {
            throw new PreparationException("Cannot choose PRF. Selected Ciphersuite is null");
        }
        if (context.getSelectedProtocolVersion() == null) {
            throw new PreparationException("Cannot choose PRF. Selected ProtocolVersion is null");
        }
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(prfAlgorithm, msg.getComputations().getPremasterSecret().getValue(),
                PseudoRandomFunction.MASTER_SECRET_LABEL, msg.getComputations().getClientRandom().getValue(),
                HandshakeByteLength.MASTER_SECRET);
    }

    private RSAPublicKey generateFreshKey() {
        KeyPairGenerator keyGen = null;
        try {
            keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
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
        msg.getComputations().setClientRandom(clientRandom);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareMasterSecret(RSAClientKeyExchangeMessage msg) {
        msg.getComputations().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getMasterSecret().getValue()));
    }

    private void prepareSerializedPublicKey(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(encrypted);
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(RSAClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }
}
