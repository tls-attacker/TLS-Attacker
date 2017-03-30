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
import java.util.Arrays;
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

    private DHPublicKeyParameters dhPublic;
    private DHPrivateKeyParameters dhPrivate;
    private byte[] serializedP;
    private byte[] serializedG;
    private ServerDHParams publicKeyParameters;
    private SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    private byte[] signature;
    private final DHEServerKeyExchangeMessage msg;

    public DHEServerKeyExchangePreparator(TlsContext context, DHEServerKeyExchangeMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {

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
        dhPrivate = (DHPrivateKeyParameters) serverKeyPair.getPrivate();

        prepareG(msg);
        prepareP(msg);
        prepareSerializedPublicKey(msg);
        preparePrivateKey(msg);
        prepareServerDHPrivateParameters(context);

        serializedP = BigIntegers.asUnsignedByteArray(msg.getP().getValue());
        prepareSerializedP(msg);
        prepareSerializedPLength(msg);

        serializedG = BigIntegers.asUnsignedByteArray(msg.getG().getValue());
        prepareSerializedG(msg);
        prepareSerializedGLength(msg);

        p = new BigInteger(1, serializedP);
        g = new BigInteger(1, serializedG);
        BigInteger y = new BigInteger(1, msg.getSerializedPublicKey().getValue());

        publicKeyParameters = new ServerDHParams(new DHPublicKeyParameters(y, new DHParameters(p, g)));
        prepareServerDHParameters(context);

        // could be extended to choose the algorithms depending on the
        // certificate
        selectedSignatureHashAlgo = context.getConfig().getSupportedSignatureAndHashAlgorithms().get(0);
        prepareSignatureAlgorithm(msg);
        prepareHashAlgorithm(msg);

        prepareClientRandom(msg);
        prepareServerRandom(msg);
        signature = generateSignature(selectedSignatureHashAlgo);
        prepareSignature(msg);
        prepareSignatureLength(msg);

    }

    private byte[] generateToBeSigned() {
        byte[] dhParams = ArrayConverter.concatenate(ArrayConverter.intToBytes(msg.getComputations()
                .getSerializedPLength().getValue(), HandshakeByteLength.DH_P_LENGTH), msg.getComputations()
                .getSerializedP().getValue(), ArrayConverter.intToBytes(msg.getComputations().getSerializedGLength()
                .getValue(), HandshakeByteLength.DH_G_LENGTH), msg.getComputations().getSerializedG().getValue(),
                ArrayConverter.intToBytes(msg.getSerializedPublicKeyLength().getValue(),
                        HandshakeByteLength.DH_PUBLICKEY_LENGTH), msg.getSerializedPublicKey().getValue());
        return ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg.getComputations()
                .getServerRandom().getValue(), dhParams);

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

    private void prepareG(DHEServerKeyExchangeMessage msg) {
        msg.setG(dhPublic.getParameters().getG());
        LOGGER.debug("G: " + msg.getG().getValue());
    }

    private void prepareP(DHEServerKeyExchangeMessage msg) {
        msg.setP(dhPublic.getParameters().getP());
        LOGGER.debug("P: " + msg.getP().getValue());
    }

    private void prepareSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(dhPublic.getY().toByteArray());
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private void preparePrivateKey(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(dhPrivate.getX());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue());
    }

    private void prepareServerDHPrivateParameters(TlsContext context) {
        context.setServerDHPrivateKeyParameters(dhPrivate);
        LOGGER.debug("ServerDHPrivateKeyParameters: " + context.getServerDHPrivateKeyParameters());
    }

    private void prepareSerializedP(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setSerializedP(serializedP);
        LOGGER.debug("SerializedP: " + Arrays.toString(msg.getComputations().getSerializedP().getValue()));
    }

    private void prepareSerializedPLength(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setSerializedPLength(msg.getComputations().getSerializedP().getValue().length);
        LOGGER.debug("SerializedPLength: " + msg.getComputations().getSerializedPLength().getValue());
    }

    private void prepareSerializedG(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setSerializedG(serializedG);
        LOGGER.debug("SerializedG: " + Arrays.toString(msg.getComputations().getSerializedG().getValue()));
    }

    private void prepareSerializedGLength(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setSerializedGLength(msg.getComputations().getSerializedG().getValue().length);
        LOGGER.debug("SerializedGLength: " + msg.getComputations().getSerializedGLength().getValue());
    }

    private void prepareServerDHParameters(TlsContext context) {
        context.setServerDHParameters(publicKeyParameters);
        LOGGER.debug("ServerDHParameters: " + context.getServerDHParameters());
    }

    private void prepareSignatureAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureAlgorithm(selectedSignatureHashAlgo.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
    }

    private void prepareHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setHashAlgorithm(selectedSignatureHashAlgo.getHashAlgorithm().getValue());
        LOGGER.debug("HashAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    private void prepareClientRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(context.getClientRandom());
        LOGGER.debug("ClientRandom: " + Arrays.toString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(context.getServerRandom());
        LOGGER.debug("ServerRandom: " + Arrays.toString(msg.getComputations().getServerRandom().getValue()));
    }

    private void prepareSignature(DHEServerKeyExchangeMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signatur: " + Arrays.toString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }
}
