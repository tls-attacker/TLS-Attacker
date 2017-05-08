/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<ECDHEServerKeyExchangeMessage> {

    private final ECDHEServerKeyExchangeMessage msg;

    public ECDHEServerKeyExchangePreparator(TlsContext ctx, ECDHEServerKeyExchangeMessage msg) {
        super(ctx, msg);
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
        AsymmetricCipherKeyPair keyPair = TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), ecParams);

        ECPublicKeyParameters pubEcParams = (ECPublicKeyParameters) keyPair.getPublic();
        ECPrivateKeyParameters privEcParams = (ECPrivateKeyParameters) keyPair.getPrivate();

        prepareSerializedPublicKey(msg, pubEcParams.getQ());
        prepareSerializedPublicKeyLength(msg);

        prepareClientRandom(msg);
        prepareServerRandom(msg);
        generatePremasterSecret(msg, pubEcParams, privEcParams);
        generateMasterSecret(msg);

        SignatureAndHashAlgorithm signHashAlgo;
        signHashAlgo = context.getConfig().getSupportedSignatureAndHashAlgorithms().get(0);
        prepareSignatureAlgorithm(msg, signHashAlgo);
        prepareHashAlgorithm(msg, signHashAlgo);

        byte[] signature = generateSignature(msg, signHashAlgo);
        prepareSignature(msg, signature);
        prepareSignatureLength(msg);

    }

    private void generatePremasterSecret(ECDHEServerKeyExchangeMessage msg, ECPublicKeyParameters pubEcParams,
            ECPrivateKeyParameters privEcParams) {

        byte[] premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(pubEcParams, privEcParams);
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void generateMasterSecret(ECDHEServerKeyExchangeMessage msg) {
        if (context.getSelectedCipherSuite() == null) {
            throw new PreparationException("Cannot choose PRF. Selected Ciphersuite is null");
        }
        if (context.getSelectedProtocolVersion() == null) {
            throw new PreparationException("Cannot choose PRF. Selected ProtocolVersion is null");
        }

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());

        byte[] premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        byte[] random = ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg
                .getComputations().getServerRandom().getValue());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, premasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        msg.getComputations().setMasterSecret(masterSecret);
    }

    private byte[] generateSignatureContents(ECDHEServerKeyExchangeMessage msg) {
        // TODO: Add signature for explicit curves
        EllipticCurveType curveType = EllipticCurveType.getCurveType(msg.getCurveType().getValue());

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
                    throw new PreparationException("Failed to add namedCurve to ECDHEServerKeyExchange signature.");
                }
        }

        ecParams.write(msg.getSerializedPublicKeyLength().getValue());
        try {
            ecParams.write(msg.getSerializedPublicKey().getValue());
        } catch (IOException ex) {
            throw new PreparationException("Failed to add serializedPublicKey to ECDHEServerKeyExchange signature.");
        }

        return ArrayConverter.concatenate(msg.getComputations().getClientRandom().getValue(), msg.getComputations()
                .getServerRandom().getValue(), ecParams.toByteArray());

    }

    private byte[] generateSignature(ECDHEServerKeyExchangeMessage msg, SignatureAndHashAlgorithm algorithm) {
        try {
            PrivateKey key = context.getConfig().getPrivateKey();
            Signature instance = Signature.getInstance(algorithm.getJavaName());
            instance.initSign(key);
            instance.update(generateSignatureContents(msg));
            return instance.sign();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException ex) {
            throw new PreparationException("Could not generate Signature for ServerKeyExchange Message.", ex);
        }
    }

    private void prepareSignatureAlgorithm(ECDHEServerKeyExchangeMessage msg, SignatureAndHashAlgorithm signHashAlgo) {
        msg.setSignatureAlgorithm(signHashAlgo.getSignatureAlgorithm().getValue());
        LOGGER.debug("SignatureAlgorithm: " + msg.getSignatureAlgorithm().getValue());
    }

    private void prepareHashAlgorithm(ECDHEServerKeyExchangeMessage msg, SignatureAndHashAlgorithm signHashAlgo) {
        msg.setHashAlgorithm(signHashAlgo.getHashAlgorithm().getValue());
        LOGGER.debug("HashAlgorithm: " + msg.getHashAlgorithm().getValue());
    }

    private void prepareClientRandom(ECDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(context.getClientRandom());
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareServerRandom(ECDHEServerKeyExchangeMessage msg) {
        msg.getComputations().setServerRandom(context.getServerRandom());
        LOGGER.debug("ServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getServerRandom().getValue()));
    }

    private void prepareSignature(ECDHEServerKeyExchangeMessage msg, byte[] signature) {
        msg.setSignature(signature);
        LOGGER.debug("Signatur: " + ArrayConverter.bytesToHexString(msg.getSignature().getValue()));
    }

    private void prepareSignatureLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSignatureLength(msg.getSignature().getValue().length);
        LOGGER.debug("SignatureLength: " + msg.getSignatureLength().getValue());

    }

    private void prepareSerializedPublicKey(ECDHEServerKeyExchangeMessage msg, ECPoint pubKey) {
        ECPointFormat[] formats = pointFormatsFromByteArray(msg.getComputations().getEcPointFormatList().getValue());
        try {
            byte[] serializedPubKey = ECCUtilsBCWrapper.serializeECPoint(formats, pubKey);
            msg.setSerializedPublicKey(serializedPubKey);
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize EC public key", ex);
        }

        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(ECDHEServerKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void generatePointFormatList(ECDHEServerKeyExchangeMessage msg) {
        List<ECPointFormat> serverPointFormats = context.getConfig().getPointFormats();

        if (serverPointFormats == null || serverPointFormats.isEmpty()) {
            throw new PreparationException("Don't know which point format to use for ECDHE. "
                    + "Check if pointFormats is set in config.");
        }

        List<ECPointFormat> sharedPointFormats = new ArrayList<>(serverPointFormats);

        if (!context.getConfig().isEnforceSettings()) {
            List<ECPointFormat> clientPointFormats = context.getClientPointFormatsList();
            for (ECPointFormat f : sharedPointFormats) {
                if (!clientPointFormats.contains(f)) {
                    sharedPointFormats.remove(f);
                }
            }
        }

        if (sharedPointFormats.isEmpty()) {
            sharedPointFormats = serverPointFormats;
        }

        msg.getComputations().setEcPointFormatList(pointFormatsToByteArray(sharedPointFormats));
    }

    private ECDomainParameters generateEcParameters(ECDHEServerKeyExchangeMessage msg) {

        NamedCurve[] curves = namedCurvesFromByteArray(msg.getComputations().getNamedCurveList().getValue());
        ECPointFormat[] formats = pointFormatsFromByteArray(msg.getComputations().getEcPointFormatList().getValue());

        InputStream is = new ByteArrayInputStream(ArrayConverter.concatenate(
                new byte[] { msg.getCurveType().getValue() }, msg.getNamedCurve().getValue()));

        ECDomainParameters ecParams;
        try {
            ecParams = ECCUtilsBCWrapper.readECParameters(curves, formats, is);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }

        LOGGER.debug("params.curve: " + ecParams.getCurve());
        LOGGER.debug("params.N: " + ecParams.getN());

        return ecParams;
    }

    private void generateNamedCurveList(ECDHEServerKeyExchangeMessage msg) {
        List<NamedCurve> serverCurves = context.getConfig().getNamedCurves();

        if (serverCurves == null || serverCurves.isEmpty()) {
            throw new PreparationException("Don't know which elliptic curves are supported by the "
                    + "server. Check if namedCurves is set in config.");
        }

        List<NamedCurve> sharedCurves = new ArrayList<>(serverCurves);
        if (!context.getConfig().isEnforceSettings()) {

            List<NamedCurve> clientCurves = context.getClientNamedCurvesList();
            for (NamedCurve c : sharedCurves) {
                if (!clientCurves.contains(c)) {
                    sharedCurves.remove(c);
                }
            }

            if (sharedCurves.isEmpty()) {
                sharedCurves = serverCurves;
            }
        }

        msg.getComputations().setNamedCurveList(namedCurvesToByteArray(sharedCurves));
    }

    private void prepareCurveType(ECDHEServerKeyExchangeMessage msg) {
        // TODO: curveType should come from config or, if client requested, from
        // context, shouldnt it? There's no config entry at the moment.
        msg.setCurveType(EllipticCurveType.NAMED_CURVE.getValue());
    }

    private void prepareNamedCurve(ECDHEServerKeyExchangeMessage msg) {
        NamedCurve[] curves = namedCurvesFromByteArray(msg.getComputations().getNamedCurveList().getValue());
        msg.setNamedCurve(curves[0].getValue());
    }

    // Don't know how you handle ModifiableByteArrays... this helpers might
    // not be necessary. But if so, they should probably be generalized and
    // placed in the appropriate place.
    public byte[] pointFormatsToByteArray(List<ECPointFormat> pointFormats) {
        if (pointFormats == null || pointFormats.isEmpty()) {
            return null;
        }
        byte[] b = new byte[pointFormats.size()];
        for (int i = 0; i < b.length; i++) {
            b[i] = pointFormats.get(i).getValue();
        }
        return b;
    }

    public ECPointFormat[] pointFormatsFromByteArray(byte[] formats) {
        if (formats == null || formats.length == 0) {
            return null;
        }
        ECPointFormat[] arr = new ECPointFormat[formats.length];
        for (int i = 0; i < formats.length; i++) {
            arr[i] = ECPointFormat.getECPointFormat(formats[i]);
        }
        return arr;
    }

    public byte[] namedCurvesToByteArray(List<NamedCurve> curves) {
        if (curves == null || curves.isEmpty()) {
            return null;
        }
        byte[][] b = new byte[curves.size()][];
        for (int i = 0; i < b.length; i++) {
            b[i] = curves.get(i).getValue();
        }

        return ArrayConverter.concatenate(b);
    }

    // Could be easily generalized if NamedCurve.getNamedCurve and
    // ECPointFormat.getECPointFormat
    // would be called NamedCurve.getName and ECPointFormat.getName.
    public NamedCurve[] namedCurvesFromByteArray(byte[] sourceBytes) {
        if (sourceBytes == null || sourceBytes.length == 0) {
            return null;
        }

        if (sourceBytes.length % NamedCurve.LENGTH != 0) {
            throw new IllegalArgumentException("Failed to convert byte array. "
                    + "Source array size is not a multiple of destination type size.");
        }

        int elementSize = NamedCurve.LENGTH;
        int numElements = sourceBytes.length / elementSize;
        NamedCurve[] arr = new NamedCurve[numElements];
        for (int i = 0; i < numElements; i++) {
            int j = i * elementSize;
            arr[i] = NamedCurve.getNamedCurve(Arrays.copyOfRange(sourceBytes, j, j + elementSize));
        }
        return arr;
    }
}
