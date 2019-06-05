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
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.math.ec.ECPoint;

public class ECDHEServerKeyExchangePreparator<T extends ECDHEServerKeyExchangeMessage> extends
        ServerKeyExchangePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final T msg;
    protected ECPublicKeyParameters pubEcParams;
    protected ECPrivateKeyParameters privEcParams;

    public ECDHEServerKeyExchangePreparator(Chooser chooser, T msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        setEcDhParams();
        prepareEcDhParams();
        SignatureAndHashAlgorithm signHashAlgo;
        signHashAlgo = chooser.getSelectedSigHashAlgorithm();
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
        preparePrivateKey(msg);
        prepareSerializedPublicKey(msg, pubEcParams.getQ());
        prepareSerializedPublicKeyLength(msg);
        prepareClientServerRandom(msg);
    }

    protected void setEcDhParams() {
        msg.prepareComputations();
        selectNamedGroup(msg);
        selectPointFormat(msg);
        prepareCurveType(msg);
        prepareNamedGroup(msg);

        ECDomainParameters ecParams = generateEcParameters(msg);
        AsymmetricCipherKeyPair keyPair = TlsECCUtils.generateECKeyPair(chooser.getContext().getBadSecureRandom(),
                ecParams);

        pubEcParams = (ECPublicKeyParameters) keyPair.getPublic();
        privEcParams = (ECPrivateKeyParameters) keyPair.getPrivate();
    }

    protected ECDomainParameters generateEcParameters(T msg) {

        if (msg.getComputations() == null) {
            throw new PreparationException("Message computations not initialized");
        }

        if (msg.getComputations().getNamedGroup() == null || msg.getComputations().getNamedGroup().getValue() == null) {
            throw new PreparationException("No groups specified in message computations");
        }

        if (msg.getComputations().getEcPointFormat() == null
                || msg.getComputations().getEcPointFormat().getValue() == null) {
            throw new PreparationException("No or empty point formats specified in message computations");
        }

        NamedGroup group = NamedGroup.getNamedGroup(msg.getComputations().getNamedGroup().getValue());
        if (group == null) {
            group = chooser.getConfig().getDefaultSelectedNamedGroup();
        }

        ECPointFormat format = ECPointFormat.getECPointFormat(msg.getComputations().getEcPointFormat().getValue());
        if (format == null) {
            format = chooser.getConfig().getDefaultSelectedPointFormat();
        }
        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { msg.getGroupType().getValue() }, msg.getNamedGroup().getValue()));

        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(new NamedGroup[] { group }, new ECPointFormat[] { format },
                    is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }
        return ecParams;
    }

    protected void selectPointFormat(T msg) {
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
        msg.getComputations().setEcPointFormat(selectedFormat.getValue());
    }

    protected void selectNamedGroup(T msg) {
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
        msg.getComputations().setNamedGroupList(namedGroup.getValue());
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

    protected void prepareSerializedPublicKey(T msg, ECPoint pubKey) {
        ECPointFormat format;
        format = ECPointFormat.getECPointFormat(msg.getComputations().getEcPointFormat().getValue());
        if (format == null) {
            LOGGER.warn("Could not transform ECPointFormat back to a valid ecPointFormat from Modification");
        }
        try {
            byte[] serializedPubKey = ECCUtilsBCWrapper.serializeECPoint(new ECPointFormat[] { format }, pubKey);
            msg.setPublicKey(serializedPubKey);
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize EC public key", ex);
        }
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
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
        }
        msg.setNamedGroup(group.getValue());
    }

    protected void preparePrivateKey(T msg) {
        msg.getComputations().setPrivateKey(privEcParams.getD());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }
}
