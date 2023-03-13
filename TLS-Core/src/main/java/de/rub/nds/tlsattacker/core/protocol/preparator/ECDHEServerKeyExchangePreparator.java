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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHEServerKeyExchangePreparator<T extends ECDHEServerKeyExchangeMessage>
        extends ServerKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;

    public ECDHEServerKeyExchangePreparator(Chooser chooser, T msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {

        msg.prepareKeyExchangeComputations();
        msg.getKeyExchangeComputations()
                .setPrivateKey(chooser.getConfig().getDefaultServerEphemeralEcPrivateKey());

        prepareCurveType(msg);
        prepareEcDhParams();

        SignatureAndHashAlgorithm signHashAlgo;
        signHashAlgo = chooseSignatureAndHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg, signHashAlgo);
        byte[] signature = generateSignature(signHashAlgo, generateSignatureContents(msg));
        prepareSignature(msg, signature);
        prepareSignatureLength(msg);
    }

    protected void prepareEcDhParams() {
        NamedGroup namedGroup = selectNamedGroup(msg);
        msg.getKeyExchangeComputations().setNamedGroup(namedGroup.getValue());
        prepareNamedGroup(msg);
        // Rereading NamedGroup
        namedGroup =
                NamedGroup.getNamedGroup(
                        msg.getKeyExchangeComputations().getNamedGroup().getValue());
        if (namedGroup == null) {
            LOGGER.warn(
                    "Could not deserialize group from computations. Using default group instead");
            namedGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
        }
        ECPointFormat pointFormat = selectPointFormat(msg);
        msg.getKeyExchangeComputations().setEcPointFormat(pointFormat.getValue());
        // Rereading EcPointFormat
        pointFormat =
                ECPointFormat.getECPointFormat(
                        msg.getKeyExchangeComputations().getEcPointFormat().getValue());
        if (pointFormat == null) {
            LOGGER.warn(
                    "Could not deserialize group from computations. Using default point format instead");
            pointFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        }

        // Compute publicKey
        EllipticCurve curve =
                ((NamedEllipticCurveParameters) namedGroup.getGroupParameters()).getCurve();
        LOGGER.debug("NamedGroup: {} ", namedGroup.name());
        byte[] publicKeyBytes;
        if (!namedGroup.isShortWeierstrass()) {
            RFC7748Curve rfcCurve = (RFC7748Curve) curve;
            publicKeyBytes =
                    rfcCurve.computePublicKey(
                            msg.getKeyExchangeComputations().getPrivateKey().getValue());
        } else if (namedGroup.isCurve()) {
            Point publicKey =
                    curve.mult(
                            msg.getKeyExchangeComputations().getPrivateKey().getValue(),
                            curve.getBasePoint());
            publicKeyBytes =
                    PointFormatter.formatToByteArray(
                            (NamedEllipticCurveParameters) (namedGroup.getGroupParameters()),
                            publicKey,
                            pointFormat.getFormat());
        } else {
            LOGGER.warn(
                    "Could not set public key. The selected curve is probably not a real curve. Using empty public key instead");
            publicKeyBytes = new byte[0];
        }
        msg.setPublicKey(publicKeyBytes);
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        prepareClientServerRandom(msg);
    }

    protected ECPointFormat selectPointFormat(T msg) {
        ECPointFormat selectedFormat;
        if (chooser.getConfig().isEnforceSettings()) {
            selectedFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        } else {
            Set<ECPointFormat> serverSet =
                    new HashSet<>(chooser.getConfig().getDefaultServerSupportedPointFormats());
            Set<ECPointFormat> clientSet = new HashSet<>(chooser.getClientSupportedPointFormats());
            serverSet.retainAll(clientSet);
            if (serverSet.isEmpty()) {
                LOGGER.warn("No common ECPointFormat - falling back to default");
                selectedFormat = chooser.getConfig().getDefaultSelectedPointFormat();
            } else {
                if (serverSet.contains(chooser.getConfig().getDefaultSelectedPointFormat())) {
                    selectedFormat = chooser.getConfig().getDefaultSelectedPointFormat();
                } else {
                    selectedFormat = (ECPointFormat) serverSet.toArray()[0];
                }
            }
        }
        return selectedFormat;
    }

    protected NamedGroup selectNamedGroup(T msg) {
        NamedGroup namedGroup;
        if (chooser.getConfig().isEnforceSettings()) {
            namedGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
        } else {
            Set<NamedGroup> serverSet =
                    new HashSet<>(chooser.getConfig().getDefaultServerNamedGroups());
            Set<NamedGroup> clientSet = new HashSet<>(chooser.getClientSupportedNamedGroups());
            serverSet.retainAll(clientSet);
            if (serverSet.isEmpty()) {
                LOGGER.warn("No common NamedGroup - falling back to default");
                namedGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
            } else {
                if (serverSet.contains(chooser.getConfig().getDefaultSelectedNamedGroup())) {
                    namedGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
                } else {
                    namedGroup = (NamedGroup) serverSet.toArray()[0];
                }
            }
        }
        if (!namedGroup.isCurve() || namedGroup.isGost()) {
            NamedGroup previousNamedGroup = namedGroup;
            namedGroup = NamedGroup.SECP256R1;
            LOGGER.warn(
                    "NamedGroup {} is not suitable for ECDHEServerKeyExchange message. Using {} instead.",
                    previousNamedGroup,
                    namedGroup);
        }
        return namedGroup;
    }

    protected byte[] generateSignatureContents(T msg) {
        EllipticCurveType curveType = chooser.getEcCurveType();
        ByteArrayOutputStream ecParams = new ByteArrayOutputStream();
        switch (curveType) {
            case EXPLICIT_PRIME:
            case EXPLICIT_CHAR2:
                throw new UnsupportedOperationException(
                        "Signing of explicit curves not implemented yet.");
            case NAMED_CURVE:
                ecParams.write(curveType.getValue());
                try {
                    ecParams.write(msg.getNamedGroup().getValue());
                } catch (IOException ex) {
                    throw new PreparationException(
                            "Failed to add named group to ECDHEServerKeyExchange signature.", ex);
                }
                break;
            default:
                throw new UnsupportedOperationException("Unsupported curve type");
        }

        ecParams.write(msg.getPublicKeyLength().getValue());
        try {
            ecParams.write(msg.getPublicKey().getValue());
        } catch (IOException ex) {
            throw new PreparationException(
                    "Failed to add serializedPublicKey to ECDHEServerKeyExchange signature.", ex);
        }

        return ArrayConverter.concatenate(
                msg.getKeyExchangeComputations().getClientServerRandom().getValue(),
                ecParams.toByteArray());
    }

    protected void prepareSignatureAndHashAlgorithm(T msg, SignatureAndHashAlgorithm signHashAlgo) {
        msg.setSignatureAndHashAlgorithm(signHashAlgo.getByteValue());
        LOGGER.debug(
                "SignatureAndHashAlgorithm: {}", msg.getSignatureAndHashAlgorithm().getValue());
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

    protected void prepareSignature(T msg, byte[] signature) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: {}", msg.getSignature().getValue());
    }

    protected void prepareSignatureLength(T msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void prepareCurveType(T msg) {
        msg.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
    }

    protected void prepareNamedGroup(T msg) {
        NamedGroup group;
        group =
                NamedGroup.getNamedGroup(
                        msg.getKeyExchangeComputations().getNamedGroup().getValue());
        if (group == null) {
            LOGGER.warn(
                    "Could not deserialize group from computations. Using default group instead");
            group = chooser.getConfig().getDefaultSelectedNamedGroup();
        }
        msg.setNamedGroup(group.getValue());
    }
}
