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
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX25519Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.ForgivingX448Curve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECDHEServerKeyExchangePreparator<T extends ECDHEServerKeyExchangeMessage> extends
        ServerKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;

    public ECDHEServerKeyExchangePreparator(Chooser chooser, T msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {

        msg.prepareComputations();
        msg.getComputations().setPrivateKey(chooser.getConfig().getDefaultServerEcPrivateKey());

        prepareCurveType(msg);
        prepareEcDhParams();

        SignatureAndHashAlgorithm signHashAlgo = chooser.getSelectedSigHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg, signHashAlgo);
        byte[] signature = new byte[0];
        try {
            signature = generateSignature(msg, signHashAlgo);
        } catch (CryptoException E) {
            LOGGER.warn("Could not generate Signature! Using empty one instead!", E);
        }
        prepareSignature(msg, signature);
        prepareSignatureLength(msg);
    }

    protected void prepareEcDhParams() {
        NamedGroup namedGroup = selectNamedGroup(msg);
        msg.getComputations().setNamedGroup(namedGroup.getValue());
        prepareNamedGroup(msg);
        // Rereading NamedGroup
        namedGroup = NamedGroup.getNamedGroup(msg.getComputations().getNamedGroup().getValue());
        if (namedGroup == null) {
            LOGGER.warn("Could not deserialize group from computations. Using default group instead");
            namedGroup = chooser.getConfig().getDefaultSelectedNamedGroup();
        }
        ECPointFormat pointFormat = selectPointFormat(msg);
        msg.getComputations().setEcPointFormat(pointFormat.getValue());
        // Rereading EcPointFormat
        pointFormat = ECPointFormat.getECPointFormat(msg.getComputations().getEcPointFormat().getValue());
        if (pointFormat == null) {
            LOGGER.warn("Could not deserialize group from computations. Using default point format instead");
            pointFormat = chooser.getConfig().getDefaultSelectedPointFormat();
        }

        // Compute publicKey
        byte[] publicKeyBytes = null;
        if (namedGroup == NamedGroup.ECDH_X25519) {
            publicKeyBytes = ForgivingX25519Curve.computePublicKey(msg.getComputations().getPrivateKey().getValue());
        } else if (namedGroup == NamedGroup.ECDH_X448) {
            publicKeyBytes = ForgivingX448Curve.computePublicKey(msg.getComputations().getPrivateKey().getValue());
        } else if (namedGroup.isCurve()) {
            EllipticCurve curve = CurveFactory.getCurve(namedGroup);
            Point publicKey = curve.mult(msg.getComputations().getPrivateKey().getValue(), curve.getBasePoint());
            publicKeyBytes = PointFormatter.formatToByteArray(publicKey, pointFormat);
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
            Set<ECPointFormat> serverSet = new HashSet<>(chooser.getConfig().getDefaultServerSupportedPointFormats());
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
            Set<NamedGroup> serverSet = new HashSet<>(chooser.getConfig().getDefaultServerNamedGroups());
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
        return namedGroup;
    }

    protected byte[] generateSignatureContents(T msg) {
        EllipticCurveType curveType = chooser.getEcCurveType();
        ByteArrayOutputStream ecParams = new ByteArrayOutputStream();
        switch (curveType) {
            case EXPLICIT_PRIME:
            case EXPLICIT_CHAR2:
                throw new UnsupportedOperationException("Signing of explicit curves not implemented yet.");
            case NAMED_CURVE:
                ecParams.write(curveType.getValue());
                try {
                    ecParams.write(msg.getNamedGroup().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Failed to add named group to ECDHEServerKeyExchange signature.", ex);
                }
        }

        ecParams.write(msg.getPublicKeyLength().getValue());
        try {
            ecParams.write(msg.getPublicKey().getValue());
        } catch (IOException ex) {
            throw new PreparationException("Failed to add serializedPublicKey to ECDHEServerKeyExchange signature.", ex);
        }

        return ArrayConverter.concatenate(msg.getComputations().getClientServerRandom().getValue(),
                ecParams.toByteArray());

    }

    protected byte[] generateSignature(T msg, SignatureAndHashAlgorithm algorithm) throws CryptoException {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateSignatureContents(msg));
    }

    protected void prepareSignatureAndHashAlgorithm(T msg, SignatureAndHashAlgorithm signHashAlgo) {
        msg.setSignatureAndHashAlgorithm(signHashAlgo.getByteValue());
        LOGGER.debug("SignatureAndHashAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    protected void prepareClientServerRandom(T msg) {
        msg.getComputations().setClientServerRandom(
                ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom()));
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    protected void prepareSignature(T msg, byte[] signature) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
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
        group = NamedGroup.getNamedGroup(msg.getComputations().getNamedGroup().getValue());
        if (group == null) {
            LOGGER.warn("Could not deserialize group from computations. Using default group instead");
            group = chooser.getConfig().getDefaultSelectedNamedGroup();
        }
        msg.setNamedGroup(group.getValue());
    }
}
