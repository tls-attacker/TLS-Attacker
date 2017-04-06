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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
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

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

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
        message.getComputations().setP(new BigInteger(1, pArray));
        message.getComputations().setG(new BigInteger(1, gArray));
        BigInteger p = message.getComputations().getP().getValue();
        BigInteger g = message.getComputations().getG().getValue();
        DHParameters params = new DHParameters(p, g);
        KeyGenerationParameters kgp = new DHKeyGenerationParameters(RandomHelper.getBadSecureRandom(), params);
        DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
        AsymmetricCipherKeyPair serverKeyPair = null;
        try {
            keyGen.init(kgp);
            serverKeyPair = keyGen.generateKeyPair();
        } catch (IllegalArgumentException E) {
            throw new PreparationException("Could not generate KeyPair", E);
        }
        dhPublic = (DHPublicKeyParameters) serverKeyPair.getPublic();
        DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) serverKeyPair.getPrivate();
        message.setG(BigIntegers.asUnsignedByteArray(dhPublic.getParameters().getG()));
        message.setP(BigIntegers.asUnsignedByteArray(dhPublic.getParameters().getP()));
        message.setSerializedPublicKey(dhPublic.getY().toByteArray());
        message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);
        message.getComputations().setPrivateKey(dhPrivate.getX());
        context.setServerDHPrivateKeyParameters(dhPrivate);
        message.setpLength(message.getP().getValue().length);
        message.setgLength(message.getG().getValue().length);
        BigInteger y = new BigInteger(1, message.getSerializedPublicKey().getValue());
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
        byte[] dhParams = ArrayConverter.concatenate(ArrayConverter.intToBytes(message.getgLength().getValue(),
                HandshakeByteLength.DH_P_LENGTH), message.getP().getValue(), ArrayConverter.intToBytes(message
                .getgLength().getValue(), HandshakeByteLength.DH_G_LENGTH), message.getG().getValue(),
                ArrayConverter.intToBytes(message.getSerializedPublicKeyLength().getValue(),
                        HandshakeByteLength.DH_PUBLICKEY_LENGTH), message.getSerializedPublicKey().getValue());
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
