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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<DHEServerKeyExchangeMessage> {

    private DHPublicKeyParameters dhPublic;
    private DHPrivateKeyParameters dhPrivate;
    private SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    private byte[] signature;
    private final DHEServerKeyExchangeMessage msg;

    public DHEServerKeyExchangePreparator(TlsContext context, DHEServerKeyExchangeMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        setComputedG(msg);
        setComputedP(msg);
        BigInteger p = msg.getComputations().getP().getValue();
        BigInteger g = msg.getComputations().getG().getValue();
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
        dhPrivate = (DHPrivateKeyParameters) serverKeyPair.getPrivate();
        prepareP(msg);
        preparePLength(msg);
        prepareG(msg);
        prepareGLength(msg);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
        preparePrivateKey(msg);
        // TODO this should not be here
        selectedSignatureHashAlgo = context.getConfig().getSupportedSignatureAndHashAlgorithms().get(0);
        prepareSignatureAndHashAlgorithm(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);
        signature = generateSignature(selectedSignatureHashAlgo);
        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    private byte[] generateToBeSigned() {
        byte[] dhParams = ArrayConverter.concatenate(ArrayConverter.intToBytes(msg.getpLength().getValue(),
                HandshakeByteLength.DH_P_LENGTH), msg.getP().getValue(), ArrayConverter.intToBytes(msg.getgLength()
                .getValue(), HandshakeByteLength.DH_G_LENGTH), msg.getG().getValue(), ArrayConverter.intToBytes(msg
                .getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PUBLICKEY_LENGTH), msg
                .getSerializedPublicKey().getValue());
        return ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg.getComputations()
                .getServerRandom().getValue(), dhParams);

    }

    private byte[] generateSignature(SignatureAndHashAlgorithm algorithm) {
        try {
            RSAPrivateCrtKey rsakey = (RSAPrivateCrtKey) context.getConfig().getPrivateKey();
            Signature instance = Signature.getInstance(algorithm.getJavaName());
            instance.initSign(rsakey);
            instance.update(generateToBeSigned());
            return instance.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            throw new PreparationException("Could not generate Signature for DHEServerKeyExchange Message.", ex);
        }

    }

    private void prepareG(DHEServerKeyExchangeMessage msg) {
        msg.setG(BigIntegers.asUnsignedByteArray(dhPublic.getParameters().getG()));
        LOGGER.debug("G: " + ArrayConverter.bytesToHexString(msg.getG().getValue()));
    }

    private void prepareP(DHEServerKeyExchangeMessage msg) {
        msg.setP(BigIntegers.asUnsignedByteArray(dhPublic.getParameters().getP()));
        LOGGER.debug("P: " + ArrayConverter.bytesToHexString(msg.getP().getValue()));
    }

    private void prepareGLength(DHEServerKeyExchangeMessage msg) {
        msg.setgLength(msg.getG().getValue().length);
        LOGGER.debug("G Length: " + msg.getgLength().getValue());
    }

    private void preparePLength(DHEServerKeyExchangeMessage msg) {
        msg.setpLength(msg.getP().getValue().length);
        LOGGER.debug("P Length: " + msg.getpLength().getValue());
    }

    private void prepareSerializedPublicKey(DHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(dhPublic.getY().toByteArray());
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(DHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void preparePrivateKey(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(dhPrivate.getX());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue());
    }

    private void setComputedP(DHEServerKeyExchangeMessage msg) {
        byte[] pArray = context.getConfig().getFixedDHModulus();
        msg.getComputations().setP(new BigInteger(1, pArray));
        LOGGER.debug("P used for Computations: " + msg.getComputations().getP().getValue().toString(16));
    }

    private void setComputedG(DHEServerKeyExchangeMessage msg) {
        byte[] gArray = context.getConfig().getFixedDHg();
        msg.getComputations().setG(new BigInteger(1, gArray));
        LOGGER.debug("G used for Computations: " + msg.getComputations().getG().getValue().toString(16));
    }

    private void prepareSignatureAndHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    private void prepareClientRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(context.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(context.getServerRandom());
        LOGGER.debug("ServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getServerRandom().getValue()));
    }

    private void prepareSignature(DHEServerKeyExchangeMessage msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signatur: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }
}
