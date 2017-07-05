/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class ECDHEServerKeyExchangePreparator extends ServerKeyExchangePreparator<ECDHEServerKeyExchangeMessage> {

    private final ECDHEServerKeyExchangeMessage msg;
    private ECPublicKeyParameters pubEcParams;
    private ECPrivateKeyParameters privEcParams;

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

        pubEcParams = (ECPublicKeyParameters) keyPair.getPublic();
        privEcParams = (ECPrivateKeyParameters) keyPair.getPrivate();
        preparePrivateKey(msg);
        prepareSerializedPublicKey(msg, pubEcParams.getQ());
        prepareSerializedPublicKeyLength(msg);
        prepareClientRandom(msg);
        prepareServerRandom(msg);

        SignatureAndHashAlgorithm signHashAlgo;
        signHashAlgo = context.getConfig().getSupportedSignatureAndHashAlgorithms().get(0);
        prepareSignatureAlgorithm(msg, signHashAlgo);
        prepareHashAlgorithm(msg, signHashAlgo);

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
        List<ECPointFormat> sharedPointFormats = new ArrayList<>(context.getConfig().getPointFormats());

        if (sharedPointFormats.isEmpty()) {
            throw new PreparationException("Don't know which point format to use for ECDHE. "
                    + "Check if pointFormats is set in config.");
        }

        List<ECPointFormat> unsupportedFormats = new ArrayList<>();

        if (!context.getConfig().isEnforceSettings()) {
            List<ECPointFormat> clientPointFormats = context.getClientPointFormatsList();
            for (ECPointFormat f : sharedPointFormats) {
                if (!clientPointFormats.contains(f)) {
                    unsupportedFormats.add(f);
                }
            }
        }

        sharedPointFormats.removeAll(unsupportedFormats);
        if (sharedPointFormats.isEmpty()) {
            sharedPointFormats = new ArrayList<>(context.getConfig().getPointFormats());
        }

        try {
            msg.getComputations().setEcPointFormatList(ECPointFormat.pointFormatsToByteArray(sharedPointFormats));
        } catch (IOException ex) {
            throw new PreparationException("Couldn't set EC point formats in computations", ex);
        }
    }

    private void generateNamedCurveList(ECDHEServerKeyExchangeMessage msg) {
        List<NamedCurve> sharedCurves = new ArrayList<>(context.getConfig().getNamedCurves());

        if (sharedCurves.isEmpty()) {
            throw new PreparationException("Don't know which elliptic curves are supported by the "
                    + "server. Check if namedCurves is set in config.");
        }

        List<NamedCurve> unsupportedCurves = new ArrayList<>();
        if (!context.getConfig().isEnforceSettings()) {

            List<NamedCurve> clientCurves = context.getClientNamedCurvesList();
            for (NamedCurve c : sharedCurves) {
                if (!clientCurves.contains(c)) {
                    unsupportedCurves.add(c);
                }
            }

            sharedCurves.removeAll(unsupportedCurves);
            if (sharedCurves.isEmpty()) {
                sharedCurves = new ArrayList<>(context.getConfig().getNamedCurves());
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

        ecParams.write(msg.getSerializedPublicKeyLength().getValue());
        try {
            ecParams.write(msg.getSerializedPublicKey().getValue());
        } catch (IOException ex) {
            throw new PreparationException("Failed to add serializedPublicKey to ECDHEServerKeyExchange signature.", ex);
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
