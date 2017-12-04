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
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.SignatureCalculator;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.math.ec.ECPoint;

public class ECDHEServerKeyExchangePreparator<T extends ECDHEServerKeyExchangeMessage> extends
        ServerKeyExchangePreparator<T> {

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
        signHashAlgo = chooser.getConfig().getDefaultSelectedSignatureAndHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg, signHashAlgo);

        byte[] signature = generateSignature(msg, signHashAlgo);
        prepareSignature(msg, signature);
        prepareSignatureLength(msg);
    }

    protected void prepareEcDhParams() {
        preparePrivateKey(msg);
        prepareSerializedPublicKey(msg, pubEcParams.getQ());
        prepareSerializedPublicKeyLength(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);

    }

    protected void setEcDhParams() {
        msg.prepareComputations();
        generateNamedCurveList(msg);
        generatePointFormatList(msg);
        prepareCurveType(msg);
        prepareNamedCurve(msg);

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

        if (msg.getComputations().getNamedCurveList() == null
                || msg.getComputations().getNamedCurveList().getValue() == null) {
            throw new PreparationException("No curves specified in message computations");
        }

        if (msg.getComputations().getEcPointFormatList() == null
                || msg.getComputations().getEcPointFormatList().getValue() == null) {
            throw new PreparationException("No or empty point formats specified in message computations");
        }

        NamedCurve[] curves;
        try {
            curves = NamedCurve.namedCurvesFromByteArray(msg.getComputations().getNamedCurveList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            LOGGER.warn("Couldn't read list of named curves from computations.", ex);
            curves = chooser.getConfig().getDefaultEcdheNamedCurves();
        }
        ECPointFormat[] formats;
        try {
            formats = ECPointFormat.pointFormatsFromByteArray(msg.getComputations().getEcPointFormatList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            LOGGER.warn("Couldn't read list of EC point formats from computations", ex);
            formats = chooser.getConfig().getDefaultEcPointFormats();
        }

        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { msg.getCurveType().getValue() }, msg.getNamedCurve().getValue()));

        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
        } catch (IOException ex) {
            is = new ByteArrayInputStream(ArrayConverter.concatenate(
                    new byte[] { EllipticCurveType.NAMED_CURVE.getValue() }, curves[0].getValue()));
            try {
                ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
            } catch (IOException | IndexOutOfBoundsException ex1) {
                throw new PreparationException("Failed to generate EC domain parameters", ex);
            }
            LOGGER.warn("Failed to generate EC domain parameters", ex);
        }

        return ecParams;
    }

    protected void generatePointFormatList(T msg) {
        List<ECPointFormat> sharedPointFormats = new ArrayList<>(chooser.getServerSupportedPointFormats());

        if (sharedPointFormats.isEmpty()) {
            LOGGER.warn("Don't know which point format to use for ECDHE. " + "Check if pointFormats is set in config.");
            sharedPointFormats = chooser.getConfig().getDefaultServerSupportedPointFormats();
        }

        List<ECPointFormat> unsupportedFormats = new ArrayList<>();

        if (!chooser.getConfig().isEnforceSettings()) {
            List<ECPointFormat> clientPointFormats = chooser.getClientSupportedPointFormats();
            for (ECPointFormat f : sharedPointFormats) {
                if (!clientPointFormats.contains(f)) {
                    unsupportedFormats.add(f);
                }
            }
        }

        sharedPointFormats.removeAll(unsupportedFormats);
        if (sharedPointFormats.isEmpty()) {
            sharedPointFormats = new ArrayList<>(chooser.getConfig().getDefaultServerSupportedPointFormats());
        }

        try {
            msg.getComputations().setEcPointFormatList(ECPointFormat.pointFormatsToByteArray(sharedPointFormats));
        } catch (IOException ex) {
            throw new PreparationException("Couldn't set EC point formats in computations", ex);
        }
    }

    protected void generateNamedCurveList(T msg) {
        List<NamedCurve> sharedCurves = new ArrayList<>(chooser.getConfig().getNamedCurves());

        if (sharedCurves.isEmpty()) {
            throw new PreparationException("Don't know which elliptic curves are supported by the "
                    + "server. Check if namedCurves is set in config.");
        }

        List<NamedCurve> unsupportedCurves = new ArrayList<>();
        if (!chooser.getConfig().isEnforceSettings()) {

            List<NamedCurve> clientCurves = chooser.getClientSupportedNamedCurves();
            for (NamedCurve c : sharedCurves) {
                if (!clientCurves.contains(c)) {
                    unsupportedCurves.add(c);
                }
            }

            sharedCurves.removeAll(unsupportedCurves);
            if (sharedCurves.isEmpty()) {
                sharedCurves = new ArrayList<>(chooser.getConfig().getNamedCurves());
            }
        }

        try {
            msg.getComputations().setNamedCurveList(NamedCurve.namedCurvesToByteArray(sharedCurves));
        } catch (IOException ex) {
            throw new PreparationException("Couldn't set named curves in computations", ex);
        }
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
                    ecParams.write(msg.getNamedCurve().getValue());
                } catch (IOException ex) {
                    throw new PreparationException("Failed to add namedCurve to ECDHEServerKeyExchange signature.", ex);
                }
        }

        ecParams.write(msg.getPublicKeyLength().getValue());
        try {
            ecParams.write(msg.getPublicKey().getValue());
        } catch (IOException ex) {
            throw new PreparationException("Failed to add serializedPublicKey to ECDHEServerKeyExchange signature.", ex);
        }

        return ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg.getComputations()
                .getServerRandom().getValue(), ecParams.toByteArray());

    }

    protected byte[] generateSignature(T msg, SignatureAndHashAlgorithm algorithm) {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateSignatureContents(msg));
    }

    protected void prepareSignatureAndHashAlgorithm(T msg, SignatureAndHashAlgorithm signHashAlgo) {
        msg.setSignatureAndHashAlgorithm(signHashAlgo.getByteValue());
        LOGGER.debug("SignatureAndHashAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    protected void prepareClientRandom(T msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    protected void prepareServerRandom(T msg) {
        msg.getComputations().setServerRandom(chooser.getServerRandom());
        LOGGER.debug("ServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getServerRandom().getValue()));
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
        ECPointFormat[] formats;
        try {
            formats = ECPointFormat.pointFormatsFromByteArray(msg.getComputations().getEcPointFormatList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            throw new PreparationException("Couldn't read list of EC point formats from computations", ex);
        }

        try {
            byte[] serializedPubKey = ECCUtilsBCWrapper.serializeECPoint(formats, pubKey);
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

    protected void prepareNamedCurve(T msg) {
        NamedCurve[] curves;
        try {
            curves = NamedCurve.namedCurvesFromByteArray(msg.getComputations().getNamedCurveList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            LOGGER.warn("Could not get named Curves from ByteArray");
            curves = chooser.getConfig().getDefaultEcdheNamedCurves();
        }
        msg.setNamedCurve(curves[0].getValue());
    }

    protected void preparePrivateKey(T msg) {
        msg.getComputations().setPrivateKey(privEcParams.getD());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }
}
