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
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.state.TlsContext;
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

    private BigInteger publicKey;
    private SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    private byte[] signature;
    private final DHEServerKeyExchangeMessage msg;

    public DHEServerKeyExchangePreparator(Chooser chooser, DHEServerKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        setComputedGenerator(msg);
        setComputedModulus(msg);
        setComputedPrivateKey(msg);
        BigInteger modulus = msg.getComputations().getModulus().getValue();
        BigInteger generator = msg.getComputations().getGenerator().getValue();
        BigInteger privateKey = msg.getComputations().getPrivateKey().getValue();

        // Compute PublicKeys
        prepareModulus(msg);
        prepareModulusLength(msg);
        prepareGenerator(msg);
        prepareGeneratorLength(msg);
        preparePublicKey(msg);
        preparePublicKeyLength(msg);
        selectedSignatureHashAlgo = chooser.getSelectedSigHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);
        signature = generateSignature(selectedSignatureHashAlgo);
        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    private byte[] generateToBeSigned() {
        byte[] dhParams = ArrayConverter
                .concatenate(ArrayConverter.intToBytes(msg.getModulusLength().getValue(),
                        HandshakeByteLength.DH_MODULUS_LENGTH), msg.getModulus().getValue(), ArrayConverter.intToBytes(
                        msg.getGeneratorLength().getValue(), HandshakeByteLength.DH_GENERATOR_LENGTH), msg
                        .getGenerator().getValue(), ArrayConverter.intToBytes(msg.getPublicKeyLength().getValue(),
                        HandshakeByteLength.DH_PUBLICKEY_LENGTH), msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg.getComputations()
                .getServerRandom().getValue(), dhParams);

    }

    private byte[] generateSignature(SignatureAndHashAlgorithm algorithm) {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateToBeSigned());
    }

    private void prepareGenerator(DHEServerKeyExchangeMessage msg) {
        msg.setGenerator(msg.getComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    private void prepareModulus(DHEServerKeyExchangeMessage msg) {
        msg.setModulus(msg.getComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    private void prepareGeneratorLength(DHEServerKeyExchangeMessage msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: " + msg.getGeneratorLength().getValue());
    }

    private void prepareModulusLength(DHEServerKeyExchangeMessage msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    private void preparePublicKey(DHEServerKeyExchangeMessage msg) {
        msg.setPublicKey(chooser.getDhServerPublicKey().toByteArray());
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void preparePublicKeyLength(DHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void setComputedPrivateKey(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(chooser.getDhServerPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue());
    }

    private void setComputedModulus(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setModulus(chooser.getDhModulus());
        LOGGER.debug("Modulus used for Computations: " + msg.getComputations().getModulus().getValue().toString(16));
    }

    private void setComputedGenerator(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setGenerator(chooser.getDhGenerator());
        LOGGER.debug("Generator used for Computations: " + msg.getComputations().getGenerator().getValue().toString(16));
    }

    private void prepareSignatureAndHashAlgorithm(DHEServerKeyExchangeMessage msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    private void prepareClientRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(DHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(chooser.getServerRandom());
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
