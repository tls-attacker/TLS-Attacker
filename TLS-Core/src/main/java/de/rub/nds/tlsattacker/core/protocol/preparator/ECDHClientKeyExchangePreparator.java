/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.EllipticCurveType;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangePreparator extends ClientKeyExchangePreparator<ECDHClientKeyExchangeMessage> {

    private byte[] serializedPoint;
    private byte[] premasterSecret;
    private byte[] random;
    private byte[] masterSecret;
    private final ECDHClientKeyExchangeMessage msg;

    public ECDHClientKeyExchangePreparator(Chooser chooser, ECDHClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        NamedCurve usedCurve = chooser.getSelectedCurve();
        CustomECPoint serverPublicKey = chooser.getServerEcPublicKey();
        BigInteger privateKey = chooser.getClientEcPrivateKey();

        // Set everything in computations and reload
        msg.getComputations().setClientPrivateKey(privateKey);
        msg.getComputations().setServerPublicKeyX(serverPublicKey.getX());
        msg.getComputations().setServerPublicKeyY(serverPublicKey.getY());
        ECDomainParameters ecParams = getDomainParameters(chooser.getEcCurveType(), usedCurve);
        serverPublicKey = new CustomECPoint(msg.getComputations().getServerPublicKeyX().getValue(), msg
                .getComputations().getServerPublicKeyY().getValue());
        privateKey = msg.getComputations().getClientPrivateKey().getValue();
        ECPoint clientPublicKey = ecParams.getCurve().getMultiplier().multiply(ecParams.getG(), privateKey);
        CustomECPoint customClientPublicKey = new CustomECPoint(clientPublicKey.getRawXCoord().toBigInteger(),
                clientPublicKey.getRawYCoord().toBigInteger());
        msg.getComputations().setClientPublicKey(customClientPublicKey);
        try {
            premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(
                    new ECPublicKeyParameters(ecParams.getCurve().createPoint(
                            msg.getComputations().getServerPublicKeyX().getValue(),
                            msg.getComputations().getServerPublicKeyY().getValue()), ecParams),
                    new ECPrivateKeyParameters(privateKey, ecParams));
        } catch (IllegalArgumentException E) {
            throw new PreparationException("Could not compute premasterSecret.", E);
        }
        // Set and update premaster secret
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
        ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
        try {
            serializedPoint = ECCUtilsBCWrapper.serializeECPoint(formatArray, clientPublicKey);
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize clientPublicKey", ex);
        }
        prepareEcPointFormat(msg);
        prepareEcPointEncoded(msg);
        preparePublicKeyBaseX(msg, clientPublicKey);
        preparePublicKeyBaseY(msg, clientPublicKey);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
        computeMasterSecret(premasterSecret, random);
        prepareMasterSecret(msg);
    }

    private ECDomainParameters getDomainParameters(EllipticCurveType curveType, NamedCurve namedCurve) {
        InputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(new byte[] { curveType.getValue() },
                namedCurve.getValue()));
        try {
            return ECCUtilsBCWrapper.readECParameters(new NamedCurve[] { chooser.getSelectedCurve() },
                    new ECPointFormat[] { ECPointFormat.UNCOMPRESSED }, stream);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }
    }

    private void computePremasterSecret(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) {
        premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(publicKey, privateKey);
    }

    private void computeMasterSecret(byte[] preMasterSecret, byte[] random) {
        PRFAlgorithm prfAlgorithm = chooser.getPRFAlgorithm();
        masterSecret = PseudoRandomFunction.compute(prfAlgorithm, preMasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
    }

    private void preparePublicKeyBaseX(ECDHClientKeyExchangeMessage msg, ECPoint clientPublicKey) {
        msg.setPublicKeyBaseX(clientPublicKey.getRawXCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseX: " + msg.getPublicKeyBaseX().getValue());
    }

    private void preparePublicKeyBaseY(ECDHClientKeyExchangeMessage msg, ECPoint clientPublicKey) {
        msg.setPublicKeyBaseY(clientPublicKey.getRawYCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseY: " + msg.getPublicKeyBaseY().getValue());
    }

    private void prepareEcPointFormat(ECDHClientKeyExchangeMessage msg) {
        msg.setEcPointFormat(serializedPoint[0]);
        LOGGER.debug("EcPointFormat: " + msg.getEcPointFormat().getValue());
    }

    private void prepareEcPointEncoded(ECDHClientKeyExchangeMessage msg) {
        msg.setEcPointEncoded(Arrays.copyOfRange(serializedPoint, 1, serializedPoint.length));
        LOGGER.debug("EcPointEncoded: " + ArrayConverter.bytesToHexString(msg.getEcPointEncoded().getValue()));
    }

    private void prepareSerializedPublicKey(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKey(serializedPoint);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    private void preparePremasterSecret(ECDHClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareClientRandom(ECDHClientKeyExchangeMessage msg) {
        // TODO this is spooky
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(random);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareMasterSecret(ECDHClientKeyExchangeMessage msg) {
        msg.getComputations().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getMasterSecret().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        try {
            msg.prepareComputations();
            List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            short[] pointFormats = ECCUtilsBCWrapper.convertPointFormats(formatArray);
            ECPublicKeyParameters clientPublicKey = TlsECCUtils.deserializeECPublicKey(pointFormats,
                    getDomainParameters(chooser.getEcCurveType(), chooser.getSelectedCurve()), msg.getPublicKey()
                            .getValue());
            CustomECPoint customClientKey = new CustomECPoint(clientPublicKey.getQ().getRawXCoord().toBigInteger(),
                    clientPublicKey.getQ().getRawYCoord().toBigInteger());
            msg.getComputations().setClientPublicKey(customClientKey);

            BigInteger privatekey = chooser.getServerEcPrivateKey();
            computePremasterSecret(clientPublicKey,
                    new ECPrivateKeyParameters(privatekey, clientPublicKey.getParameters()));
            preparePremasterSecret(msg);
            prepareClientRandom(msg);
            computeMasterSecret(premasterSecret, random);
            prepareMasterSecret(msg);
        } catch (IOException ex) {
            throw new PreparationException("Could prepare ECDHClientKeyExchange Message after Parse", ex);
        }
    }
}
