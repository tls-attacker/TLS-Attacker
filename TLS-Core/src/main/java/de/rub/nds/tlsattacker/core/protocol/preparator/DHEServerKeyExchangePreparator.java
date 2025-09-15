/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.FfdhGroupParameters;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.selection.SignatureAndHashAlgorithmSelector;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DHEServerKeyExchangePreparator<T extends DHEServerKeyExchangeMessage>
        extends ServerKeyExchangePreparator<T> {

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
        if (chooser.getSelectedCipherSuite().isExport()) {
            setDheExportParams();
        } else {
            setDheParams();
        }
        // Compute PublicKeys
        preparePublicKey(msg);
        prepareDheParams();
        selectedSignatureHashAlgo =
                SignatureAndHashAlgorithmSelector.selectSignatureAndHashAlgorithm(chooser, false);
        prepareSignatureAndHashAlgorithm(msg);
        signature = generateSignature(selectedSignatureHashAlgo, generateToBeSigned());
        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    protected void setDheParams() {
        msg.prepareKeyExchangeComputations();
        NamedGroup ffdhGroup = getMatchingNamedGroup();
        if (ffdhGroup == null) {
            setComputedGenerator(msg);
            setComputedModulus(msg);
        } else {
            setNamedGroupParameters(msg, ffdhGroup);
        }
        setComputedPrivateKey(msg);
    }

    protected void setDheExportParams() {
        msg.prepareKeyExchangeComputations();
        msg.getKeyExchangeComputations()
                .setGenerator(chooser.getConfig().getDefaultServerDhExportGenerator());
        LOGGER.debug("Generator: {}", msg.getKeyExchangeComputations().getGenerator().getValue());
        msg.getKeyExchangeComputations()
                .setModulus(chooser.getConfig().getDefaultServerDhExportModulus());
        LOGGER.debug("Modulus: {}", msg.getKeyExchangeComputations().getModulus().getValue());
        msg.getKeyExchangeComputations()
                .setPrivateKey(chooser.getConfig().getDefaultServerDhExportPrivateKey());
        LOGGER.debug("PrivateKey: {}", msg.getKeyExchangeComputations().getPrivateKey().getValue());
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
        byte[] dhParams =
                DataConverter.concatenate(
                        DataConverter.intToBytes(
                                msg.getModulusLength().getValue(),
                                HandshakeByteLength.DH_MODULUS_LENGTH),
                        msg.getModulus().getValue(),
                        DataConverter.intToBytes(
                                msg.getGeneratorLength().getValue(),
                                HandshakeByteLength.DH_GENERATOR_LENGTH),
                        msg.getGenerator().getValue(),
                        DataConverter.intToBytes(
                                msg.getPublicKeyLength().getValue(),
                                HandshakeByteLength.DH_PUBLICKEY_LENGTH),
                        msg.getPublicKey().getValue());
        return DataConverter.concatenate(
                msg.getKeyExchangeComputations().getClientServerRandom().getValue(), dhParams);
    }

    protected void prepareGenerator(T msg) {
        msg.setGenerator(msg.getKeyExchangeComputations().getGenerator().getByteArray());
        LOGGER.debug("Generator: {}", msg.getGenerator().getValue());
    }

    protected void prepareModulus(T msg) {
        msg.setModulus(msg.getKeyExchangeComputations().getModulus().getByteArray());
        LOGGER.debug("Modulus: {}", msg.getModulus().getValue());
    }

    protected void prepareGeneratorLength(T msg) {
        msg.setGeneratorLength(msg.getGenerator().getValue().length);
        LOGGER.debug("Generator Length: {}", msg.getGeneratorLength().getValue());
    }

    protected void prepareModulusLength(T msg) {
        msg.setModulusLength(msg.getModulus().getValue().length);
        LOGGER.debug("Modulus Length: {}", msg.getModulusLength().getValue());
    }

    protected void preparePublicKey(T msg) {
        BigInteger publicKey = chooser.getServerEphemeralDhPublicKey();
        try {

            BigInteger generator = msg.getKeyExchangeComputations().getGenerator().getValue();
            publicKey =
                    generator.modPow(
                            msg.getKeyExchangeComputations().getPrivateKey().getValue(),
                            msg.getKeyExchangeComputations().getModulus().getValue());
        } catch (Exception e) {
            LOGGER.warn("Could not compute public key", e);
        }
        msg.setPublicKey(DataConverter.bigIntegerToByteArray(publicKey));
        LOGGER.debug("PublicKey: {}", msg.getPublicKey().getValue());
    }

    protected void preparePublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: {}", msg.getPublicKeyLength().getValue());
    }

    protected void setComputedPrivateKey(T msg) {
        msg.getKeyExchangeComputations().setPrivateKey(chooser.getServerEphemeralDhPrivateKey());
        LOGGER.debug("PrivateKey: {}", msg.getKeyExchangeComputations().getPrivateKey().getValue());
    }

    protected void setComputedModulus(T msg) {
        msg.getKeyExchangeComputations().setModulus(chooser.getServerEphemeralDhModulus());
        LOGGER.debug(
                "Modulus used for Computations: {}",
                msg.getKeyExchangeComputations().getModulus().getValue().toString(16));
    }

    protected void setComputedGenerator(T msg) {
        msg.getKeyExchangeComputations().setGenerator(chooser.getServerEphemeralDhGenerator());
        LOGGER.debug(
                "Generator used for Computations: {}",
                msg.getKeyExchangeComputations().getGenerator().getValue().toString(16));
    }

    protected void prepareSignatureAndHashAlgorithm(T msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug("SignatureAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getKeyExchangeComputations()
                .setClientServerRandom(
                        DataConverter.concatenate(
                                chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug(
                "ClientServerRandom: {}",
                msg.getKeyExchangeComputations().getClientServerRandom().getValue());
    }

    protected void prepareSignature(T msg) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }

    protected void prepareSignatureLength(T msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: {}", msg.getSignatureLength().getValue());
    }

    private void setNamedGroupParameters(T msg, NamedGroup chosenGroup) {
        LOGGER.debug(
                "Negotiating NamedGroup {} for Server Key Exchange message", chosenGroup.name());
        FfdhGroupParameters ffdhGroup = (FfdhGroupParameters) chosenGroup.getGroupParameters();
        msg.getKeyExchangeComputations().setGenerator(ffdhGroup.getGenerator());
        msg.getKeyExchangeComputations().setModulus(ffdhGroup.getModulus());
    }

    private NamedGroup getMatchingNamedGroup() {
        if (chooser.getContext().getTlsContext().getClientNamedGroupsList() != null) {
            for (NamedGroup serverGroup : chooser.getConfig().getDefaultServerNamedGroups()) {
                if (serverGroup.isDhGroup()
                        && chooser.getContext()
                                .getTlsContext()
                                .getClientNamedGroupsList()
                                .contains(serverGroup)) {
                    return serverGroup;
                }
            }
        } else if (chooser.getConfig().getDefaultSelectedNamedGroup().isDhGroup()) {
            return chooser.getConfig().getDefaultSelectedNamedGroup();
        }
        return null;
    }
}
