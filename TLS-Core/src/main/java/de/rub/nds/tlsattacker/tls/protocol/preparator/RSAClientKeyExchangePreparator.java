/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
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

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");
    
    private final RSAClientKeyExchangeMessage message;

    public RSAClientKeyExchangePreparator(TlsContext context, RSAClientKeyExchangeMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        RSAPublicKey publicKey;
        if (context.getServerPublicKey() == null || !"RSA".equals(context.getServerPublicKey().getAlgorithm())) {
            publicKey = generateFreshKey();
        } else {
            publicKey = (RSAPublicKey) context.getServerPublicKey();
        }

        int keyByteLength = publicKey.getModulus().bitLength() / 8;
        // the number of random bytes in the pkcs1 message
        int randomByteLength = keyByteLength - HandshakeByteLength.PREMASTER_SECRET - 3;
        byte[] padding = new byte[randomByteLength];
        RandomHelper.getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);
        message.getComputations().setPadding(padding);
        byte[] premasterSecret = generatePremasterSecret();
        message.getComputations().setPremasterSecret(premasterSecret);
        // TODO what are those magic numbers?
        message.getComputations().setPlainPaddedPremasterSecret(
                ArrayConverter.concatenate(new byte[] { 0x00, 0x02 }, padding, new byte[] { 0x00 }, message
                        .getComputations().getPremasterSecret().getValue()));

        byte[] paddedPremasterSecret = message.getComputations().getPlainPaddedPremasterSecret().getValue();

        byte[] clientRandom = context.getClientServerRandom();
        message.getComputations().setClientRandom(clientRandom);

        byte[] masterSecret = generateMasterSecret();
        message.getComputations().setMasterSecret(masterSecret);
        try {
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            if (paddedPremasterSecret.length == 0) {
                paddedPremasterSecret = new byte[] { 0 };
            }
            if (new BigInteger(paddedPremasterSecret).compareTo(publicKey.getModulus()) == 1) {
                throw new PreparationException("Trying to encrypt more Data than moduls Size!");
            }
            byte[] encrypted = null;
            try {
                encrypted = cipher.doFinal(paddedPremasterSecret);
            } catch (org.bouncycastle.crypto.DataLengthException | ArrayIndexOutOfBoundsException E) {
                // too much data for RSA block
                throw new PreparationException("Too much data for RSA-Block", E);
            }
            message.setSerializedPublicKey(encrypted);
            message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);
        } catch (BadPaddingException | IllegalBlockSizeException | NoSuchProviderException | InvalidKeyException
                | NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new PreparationException("Could not prepare RSAClientKeyExchange Message");
        }

    }

    private byte[] generatePremasterSecret() {
        byte[] premasterSecret = new byte[HandshakeByteLength.PREMASTER_SECRET];
        RandomHelper.getRandom().nextBytes(premasterSecret);
        premasterSecret[0] = context.getSelectedProtocolVersion().getMajor();
        premasterSecret[1] = context.getSelectedProtocolVersion().getMinor();
        return premasterSecret;
    }

    private byte[] generateMasterSecret() {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(prfAlgorithm, message.getComputations().getPremasterSecret().getValue(),
                PseudoRandomFunction.MASTER_SECRET_LABEL, message.getComputations().getClientRandom().getValue(),
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
}
