/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.RSAServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        signature = generateSignature(selectedSignatureHashAlgo, generateToBeSigned());
        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    protected void setRsaParams() {
        msg.prepareKeyExchangeComputations();
        msg.getKeyExchangeComputations()
                .setPrivateKey(chooser.getConfig().getDefaultServerEphemeralRsaExportPrivateKey());
        msg.getKeyExchangeComputations()
                .setModulus(chooser.getConfig().getDefaultServerEphemeralRsaExportModulus());
        msg.getKeyExchangeComputations()
                .setPublicExponent(chooser.getConfig().getDefaultServerEphemeralRsaExportModulus());
    }

    protected void prepareRsaParams() {
        msg.setModulus(msg.getKeyExchangeComputations().getModulus().getByteArray());
        msg.setModulusLength(msg.getModulus().getValue().length);

        msg.setPublicKey(msg.getKeyExchangeComputations().getPublicExponent().getByteArray());
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);

        prepareClientServerRandom(msg);
    }

    protected byte[] generateToBeSigned() {
        byte[] rsaParams =
                ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(
                                msg.getModulusLength().getValue(),
                                HandshakeByteLength.RSA_MODULUS_LENGTH),
                        msg.getModulus().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getPublicKeyLength().getValue(),
                                HandshakeByteLength.RSA_MODULUS_LENGTH),
                        msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(
                msg.getKeyExchangeComputations().getClientServerRandom().getValue(), rsaParams);
    }

    protected void prepareSignatureAndHashAlgorithm(T msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getKeyExchangeComputations()
                .setClientServerRandom(
                        ArrayConverter.concatenate(
                                chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug(
                "ClientServerRandom: {}",
                msg.getKeyExchangeComputations().getClientServerRandom().getValue());
    }

    protected void prepareSignature(T msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signatur: {}", msg.getSignature().getValue());
    }

    protected void prepareSignatureLength(T msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }
}
