/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ffdh.FFDHEGroup;
import de.rub.nds.tlsattacker.core.crypto.ffdh.GroupFactory;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
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
        selectedSignatureHashAlgo = chooser.getSelectedSigHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg);
        signature = generateSignature(selectedSignatureHashAlgo, generateToBeSigned());
        prepareSignature(msg);
        prepareSignatureLength(msg);
    }

    protected void setDheParams() {
        msg.prepareKeyExchangeComputations();
        NamedGroup ffdheGroup = getMatchingNamedGroup();
        if (ffdheGroup == null) {
            setComputedGenerator(msg);
            setComputedModulus(msg);
        } else {
            setNamedGroupParameters(msg, ffdheGroup);
        }
        setComputedPrivateKey(msg);
    }

    protected void setDheExportParams() {
        msg.prepareKeyExchangeComputations();
        msg.getKeyExchangeComputations().setGenerator(chooser.getConfig().getDefaultServerDhExportGenerator());
        LOGGER.debug("Generator: " + msg.getKeyExchangeComputations().getGenerator().getValue().toString(16));
        msg.getKeyExchangeComputations().setModulus(chooser.getConfig().getDefaultServerDhExportModulus());
        LOGGER.debug(
                "Modulus used for Computations: "
                + msg.getKeyExchangeComputations().getModulus().getValue().toString(16));
        msg.getKeyExchangeComputations()
                .setPrivateKey(chooser.getConfig().getDefaultServerDhExportPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getKeyExchangeComputations().getPrivateKey().getValue());
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
        byte[] dhParams
                = ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(
                                msg.getModulusLength().getValue(),
                                HandshakeByteLength.DH_MODULUS_LENGTH),
                        msg.getModulus().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getGeneratorLength().getValue(),
                                HandshakeByteLength.DH_GENERATOR_LENGTH),
                        msg.getGenerator().getValue(),
                        ArrayConverter.intToBytes(
                                msg.getPublicKeyLength().getValue(),
                                HandshakeByteLength.DH_PUBLICKEY_LENGTH),
                        msg.getPublicKey().getValue());
        return ArrayConverter.concatenate(
                msg.getKeyExchangeComputations().getClientServerRandom().getValue(), dhParams);
    }

    protected void prepareGenerator(T msg) {
        msg.setGenerator(msg.getKeyExchangeComputations().getGenerator().getByteArray());
        LOGGER.debug(
                "Generator: " + ArrayConverter.bytesToHexString(msg.getGenerator().getValue()));
    }

    protected void prepareModulus(T msg) {
        msg.setModulus(msg.getKeyExchangeComputations().getModulus().getByteArray());
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
        BigInteger publicKey = chooser.getServerDhPublicKey();
        try {

            BigInteger generator = msg.getKeyExchangeComputations().getGenerator().getValue();
            publicKey
                    = generator.modPow(
                            msg.getKeyExchangeComputations().getPrivateKey().getValue(),
                            msg.getKeyExchangeComputations().getModulus().getValue());
        } catch (Exception e) {
            LOGGER.warn("Could not compute public key", e);
        }
        msg.setPublicKey(ArrayConverter.bigIntegerToByteArray(publicKey));
        LOGGER.debug(
                "PublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void preparePublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("PublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void setComputedPrivateKey(T msg) {
        msg.getKeyExchangeComputations().setPrivateKey(chooser.getServerDhPrivateKey());
        LOGGER.debug("PrivateKey: " + msg.getKeyExchangeComputations().getPrivateKey().getValue());
    }

    protected void setComputedModulus(T msg) {
        msg.getKeyExchangeComputations().setModulus(chooser.getServerDhModulus());
        LOGGER.debug(
                "Modulus used for Computations: "
                + msg.getKeyExchangeComputations().getModulus().getValue().toString(16));
    }

    protected void setComputedGenerator(T msg) {
        msg.getKeyExchangeComputations().setGenerator(chooser.getServerDhGenerator());
        LOGGER.debug(
                "Generator used for Computations: "
                + msg.getKeyExchangeComputations().getGenerator().getValue().toString(16));
    }

    protected void prepareSignatureAndHashAlgorithm(T msg) {
        msg.setSignatureAndHashAlgorithm(selectedSignatureHashAlgo.getByteValue());
        LOGGER.debug(
                "SignatureAlgorithm: "
                + ArrayConverter.bytesToHexString(
                        msg.getSignatureAndHashAlgorithm().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getKeyExchangeComputations()
                .setClientServerRandom(
                        ArrayConverter.concatenate(
                                chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug(
                "ClientServerRandom: "
                + ArrayConverter.bytesToHexString(
                        msg.getKeyExchangeComputations().getClientServerRandom().getValue()));
    }

    protected void prepareSignature(T msg) {
        msg.setSignature(signature);
        LOGGER.debug(
                "signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    protected void prepareSignatureLength(T msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void setNamedGroupParameters(T msg, NamedGroup chosenGroup) {
        LOGGER.debug(
                "Negotiating NamedGroup {} for Server Key Exchange message", chosenGroup.name());
        FFDHEGroup ffdheGroup = GroupFactory.getGroup(chosenGroup);
        msg.getKeyExchangeComputations().setGenerator(ffdheGroup.getG());
        msg.getKeyExchangeComputations().setModulus(ffdheGroup.getP());
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
