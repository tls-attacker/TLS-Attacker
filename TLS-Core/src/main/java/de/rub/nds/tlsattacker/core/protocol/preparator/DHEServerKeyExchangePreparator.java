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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangePreparator<T extends DHEServerKeyExchangeMessage> extends
        ServerKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected BigInteger publicKey;
    protected SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    protected byte[] signature;
    protected final T msg;

    public DHEServerKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        setDheParams();
        // Compute PublicKeys
        preparePublicKey(msg);
        prepareDheParams();
        selectedSignatureHashAlgo = chooser.getSelectedSigHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg);
        signature = new byte[0];
        try {
            signature = generateSignature(selectedSignatureHashAlgo);
        } catch (CryptoException E) {
            LOGGER.warn("Could not generate Signature! Using empty one instead!", E);
        }
        prepareSignature(msg);
        prepareSignatureLength(msg);

    }

    protected void setDheParams() {
        msg.prepareComputations();
        setComputedGenerator(msg);
        setComputedModulus(msg);
        setComputedPrivateKey(msg);
    }

    protected void prepareDheParams() {
        prepareModulus(msg);
        prepareModulusLength(msg);
        prepareGenerator(msg);
        prepareGeneratorLength(msg);
        prepareClientServerRandom(msg);
        preparePublicKeyLength(msg);
    }

    protected byte[] generateToBeSigned() {
        byte[] dhParams = ArrayConverter
                .concatenate(ArrayConverter.intToBytes(msg.getModulusLength().getValue(),
                        HandshakeByteLength.DH_MODULUS_LENGTH), msg.getModulus().getValue(), ArrayConverter.intToBytes(
                        msg.getGeneratorLength().getValue(), HandshakeByteLength.DH_GENERATOR_LENGTH), msg
                        .getGenerator().getValue(), ArrayConverter.intToBytes(msg.getPublicKeyLength().getValue(),
                        HandshakeByteLength.DH_PUBLICKEY_LENGTH), msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(msg.getComputations().getClientServerRandom().getValue(), dhParams);

    }

    protected byte[] generateSignature(SignatureAndHashAlgorithm algorithm) throws CryptoException {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateToBeSigned());
    }

    protected void prepareGenerator(T msg) {
        msg.setGenerator(msg.getComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    protected void prepareModulus(T msg) {
        msg.setModulus(msg.getComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: " + ArrayConverter.bytesToHexString(msg.getModulus().getValue()));
    }

    protected void prepareGeneratorLength(T msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: " + msg.getGeneratorLength().getValue());
    }

    protected void prepareModulusLength(T msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: " + msg.getModulusLength().getValue());
    }

    protected void preparePublicKey(T msg) {
        BigInteger publicKey = chooser.getDhServerPublicKey();
        try {

            BigInteger generator = msg.getComputations().getGenerator().getValue();
            publicKey = generator.modPow(msg.getComputations().getPrivateKey().getValue(), msg.getComputations()
                    .getModulus().getValue());
        } catch (Exception E) {
            LOGGER.warn("Could not compute public key", E);
        }
        msg.setPublicKey(ArrayConverter.bigIntegerToByteArray(publicKey));
        LOGGER.debug("PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void preparePublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void setComputedPrivateKey(T msg) {
        msg.getComputations().setPrivateKey(chooser.getDhServerPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue());
    }

    protected void setComputedModulus(T msg) {
        msg.getComputations().setModulus(chooser.getServerDhModulus());
        LOGGER.debug("Modulus used for Computations: " + msg.getComputations().getModulus().getValue().toString(16));
    }

    protected void setComputedGenerator(T msg) {
        msg.getComputations().setGenerator(chooser.getServerDhGenerator());
        LOGGER.debug("Generator used for Computations: " + msg.getComputations().getGenerator().getValue().toString(16));
    }

    protected void prepareSignatureAndHashAlgorithm(T msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getComputations().setClientServerRandom(
                ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    protected void prepareSignature(T msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signatur: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    protected void prepareSignatureLength(T msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }
}
