/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.KeystoreHandler;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<DHEServerKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHEServerKeyExchangePreparator.class);

    private final DHEServerKeyExchangeMessage message;

    public DHEServerKeyExchangePreparator(TlsContext context, DHEServerKeyExchangeMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        DHPublicKeyParameters dhPublic;

        // fixed DH modulus P and DH generator G
        byte[] pArray = context.getConfig().getFixedDHModulus();
        byte[] gArray = context.getConfig().getFixedDHg();
        BigInteger p = new BigInteger(1, pArray);
        BigInteger g = new BigInteger(1, gArray);
        DHParameters params = new DHParameters(p, g);

        KeyGenerationParameters kgp = new DHKeyGenerationParameters(RandomHelper.getBadSecureRandom(), params);
        DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
        keyGen.init(kgp);
        AsymmetricCipherKeyPair serverKeyPair = keyGen.generateKeyPair();

        dhPublic = (DHPublicKeyParameters) serverKeyPair.getPublic();
        DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) serverKeyPair.getPrivate();

        message.setG(dhPublic.getParameters().getG());
        message.setP(dhPublic.getParameters().getP());
        message.setPublicKey(dhPublic.getY());
        message.getComputations().setPrivateKey(dhPrivate.getX());
        context.setServerDHPrivateKeyParameters(dhPrivate);

        byte[] serializedP = BigIntegers.asUnsignedByteArray(message.getP().getValue());
        message.getComputations().setSerializedP(serializedP);
        message.getComputations().setSerializedPLength(message.getComputations().getSerializedP().getValue().length);

        byte[] serializedG = BigIntegers.asUnsignedByteArray(message.getG().getValue());
        message.getComputations().setSerializedG(serializedG);
        message.getComputations().setSerializedGLength(message.getComputations().getSerializedG().getValue().length);

        byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(message.getPublicKey().getValue());
        message.setSerializedPublicKey(serializedPublicKey);
        message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);

        p = new BigInteger(1, serializedP);
        g = new BigInteger(1, serializedG);
        BigInteger y = new BigInteger(1, serializedPublicKey);

        ServerDHParams publicKeyParameters = new ServerDHParams(new DHPublicKeyParameters(y, new DHParameters(p, g)));
        context.setServerDHParameters(publicKeyParameters);

        // could be extended to choose the algorithms depending on the
        // certificate
        SignatureAndHashAlgorithm selectedSignatureHashAlgo = context.getConfig()
                .getSupportedSignatureAndHashAlgorithms().get(0);
        message.setSignatureAlgorithm(selectedSignatureHashAlgo.getSignatureAlgorithm().getValue());
        message.setHashAlgorithm(selectedSignatureHashAlgo.getHashAlgorithm().getValue());

        message.getComputations().setClientRandom(context.getClientRandom());
        message.getComputations().setServerRandom(context.getServerRandom());
        byte[] signature = generateSignature(selectedSignatureHashAlgo);
        message.setSignature(signature);
        message.setSignatureLength(message.getSignature().getValue().length);

    }

    private byte[] generateToBeSigned() {
        byte[] dhParams = ArrayConverter.concatenate(ArrayConverter.intToBytes(message.getComputations()
                .getSerializedPLength().getValue(), HandshakeByteLength.DH_P_LENGTH), message.getComputations()
                .getSerializedP().getValue(), ArrayConverter.intToBytes(message.getComputations()
                .getSerializedGLength().getValue(), HandshakeByteLength.DH_G_LENGTH), message.getComputations()
                .getSerializedG().getValue(), ArrayConverter.intToBytes(message.getSerializedPublicKeyLength()
                .getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH), message.getSerializedPublicKey().getValue());
        return ArrayConverter.concatenate(message.getComputations().getClientRandom().getValue(), message
                .getComputations().getServerRandom().getValue(), dhParams);

    }

    private byte[] generateSignature(SignatureAndHashAlgorithm algorithm) {
        try {
            PrivateKey key = context.getConfig().getPrivateKey();
            Signature instance = Signature.getInstance(algorithm.getJavaName());
            instance.initSign(key);
            instance.update(generateToBeSigned());
            return instance.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            throw new PreparationException("Could not generate Signature for DHEServerKeyExchange Message.", ex);
        }

    }
}
