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

/**
 *


 */
public class ECDHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<ECDHEServerKeyExchangeMessage> {

    private final ECDHEServerKeyExchangeMessage msg;
    private ECPublicKeyParameters pubEcParams;
    private ECPrivateKeyParameters privEcParams;

    public ECDHEServerKeyExchangePreparator(Chooser chooser, ECDHEServerKeyExchangeMessage msg) {
        super(chooser, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {

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
        preparePrivateKey(msg);
        prepareSerializedPublicKey(msg, pubEcParams.getQ());
        prepareSerializedPublicKeyLength(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);

        SignatureAndHashAlgorithm signHashAlgo;
        signHashAlgo = chooser.getConfig().getDefaultSelectedSignatureAndHashAlgorithm();
        prepareSignatureAndHashAlgorithm(msg, signHashAlgo);

        byte[] signature = generateSignature(msg, signHashAlgo);
        prepareSignature(msg, signature);
        prepareSignatureLength(msg);
    }

    private ECDomainParameters generateEcParameters(ECDHEServerKeyExchangeMessage msg) {

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
            throw new PreparationException("Couldn't read list of named curves from computations.", ex);
        }
        ECPointFormat[] formats;
        try {
            formats = ECPointFormat.pointFormatsFromByteArray(msg.getComputations().getEcPointFormatList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            throw new PreparationException("Couldn't read list of EC point formats from computations", ex);
        }

        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { msg.getCurveType().getValue() }, msg.getNamedCurve().getValue()));

        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }

        return ecParams;
    }

    private void generatePointFormatList(ECDHEServerKeyExchangeMessage msg) {
        List<ECPointFormat> sharedPointFormats = new ArrayList<>(chooser.getServerSupportedPointFormats());

        if (sharedPointFormats.isEmpty()) {
            throw new PreparationException("Don't know which point format to use for ECDHE. "
                    + "Check if pointFormats is set in config.");
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

    private void generateNamedCurveList(ECDHEServerKeyExchangeMessage msg) {
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

    private byte[] generateSignatureContents(ECDHEServerKeyExchangeMessage msg) {
        EllipticCurveType curveType = EllipticCurveType.getCurveType(msg.getCurveType().getValue());

        ByteArrayOutputStream ecParams = new ByteArrayOutputStream();
        switch (curveType) {
            case EXPLICIT_PRIME:
            case EXPLICIT_CHAR2:
                throw new PreparationException("Signing of explicit curves not implemented yet.");
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

    private byte[] generateSignature(ECDHEServerKeyExchangeMessage msg, SignatureAndHashAlgorithm algorithm) {
        return SignatureCalculator.generateSignature(algorithm, chooser, generateSignatureContents(msg));
    }

    private void prepareSignatureAndHashAlgorithm(ECDHEServerKeyExchangeMessage msg,
            SignatureAndHashAlgorithm signHashAlgo) {
        msg.setSignatureAndHashAlgorithm(signHashAlgo.getByteValue());
        LOGGER.debug("SignatureAndHashAlgorithm: "
                + ArrayConverter.bytesToHexString(msg.getSignatureAndHashAlgorithm().getValue()));
    }

    private void prepareClientRandom(ECDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(chooser.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(ECDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(chooser.getServerRandom());
        LOGGER.debug("ServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getServerRandom().getValue()));
    }

    private void prepareSignature(ECDHEServerKeyExchangeMessage msg, byte[] signature) {
        msg.setSignature(signature);
        LOGGER.debug("Signature: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());
    }

    private void prepareSerializedPublicKey(ECDHEServerKeyExchangeMessage msg, ECPoint pubKey) {
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

    private void prepareSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void prepareCurveType(ECDHEServerKeyExchangeMessage msg) {
        msg.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
    }

    private void prepareNamedCurve(ECDHEServerKeyExchangeMessage msg) {
        NamedCurve[] curves;
        try {
            curves = NamedCurve.namedCurvesFromByteArray(msg.getComputations().getNamedCurveList().getValue());
        } catch (IOException | ClassNotFoundException ex) {
            throw new PreparationException("Couldn't read list of named curves from computations", ex);
        }
        msg.setNamedCurve(curves[0].getValue());
    }

    private void preparePrivateKey(ECDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setPrivateKey(privEcParams.getD());
        LOGGER.debug("PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }
}
