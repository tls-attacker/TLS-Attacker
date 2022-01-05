/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class RSAServerKeyExchangePreparator<T extends RSAServerKeyExchangeMessage>
    extends ServerKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SignatureAndHashAlgorithm selectedSignatureHashAlgo;
    protected byte[] signature;
    protected final T msg;

    public RSAServerKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        setRsaParams();
        prepareRsaParams();

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

    protected void setRsaParams() {
        msg.prepareComputations();
        msg.getComputations().setPrivateKey(chooser.getServerRSAPrivateKey());
        msg.getComputations().setModulus(chooser.getServerRsaModulus());
        msg.getComputations().setPublicExponent(chooser.getServerRSAPublicKey());
    }

    protected void prepareRsaParams() {
        msg.setModulus(msg.getComputations().getModulus().getByteArray());
        msg.setModulusLength(msg.getModulus().getValue().length);

        msg.setPublicKey(msg.getComputations().getPublicExponent().getByteArray());
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);

        prepareClientServerRandom(msg);
    }

    protected byte[] generateToBeSigned() {
        byte[] rsaParams = ArrayConverter.concatenate(
            ArrayConverter.intToBytes(msg.getModulusLength().getValue(), HandshakeByteLength.RSA_MODULUS_LENGTH),
            msg.getModulus().getValue(),
            ArrayConverter.intToBytes(msg.getPublicKeyLength().getValue(), HandshakeByteLength.RSA_MODULUS_LENGTH),
            msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(msg.getComputations().getClientServerRandom().getValue(), rsaParams);

    }

    protected byte[] generateSignature(SignatureAndHashAlgorithm algorithm) throws CryptoException {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateToBeSigned());
    }

    protected void prepareSignatureAndHashAlgorithm(T msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug(
            "SignatureAlgorithm: " + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getComputations()
            .setClientServerRandom(ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom()));
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
