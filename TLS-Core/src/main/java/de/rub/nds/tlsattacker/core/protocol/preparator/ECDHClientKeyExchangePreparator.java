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
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
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

public class ECDHClientKeyExchangePreparator<T extends ECDHClientKeyExchangeMessage> extends
        ClientKeyExchangePreparator<T> {

    protected byte[] serializedPoint;
    protected byte[] premasterSecret;
    protected byte[] random;
    protected final T msg;

    public ECDHClientKeyExchangePreparator(Chooser chooser, T message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.prepareComputations();
        NamedGroup usedCurve = chooser.getSelectedNamedGroup();
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
            premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(new ECPublicKeyParameters(ecParams.getCurve()
                    .createPoint(serverPublicKey.getX(), serverPublicKey.getY()), ecParams),
                    new ECPrivateKeyParameters(privateKey, ecParams));
        } catch (IllegalArgumentException E) {
            premasterSecret = chooser.getPreMasterSecret();
        }
        // Set and update premaster secret
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
        ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
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
    }

    protected ECDomainParameters getDomainParameters(EllipticCurveType curveType, NamedGroup namedCurve) {
        InputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(new byte[] { curveType.getValue() },
                namedCurve.getValue()));
        try {
            return ECCUtilsBCWrapper.readECParameters(new NamedGroup[] { chooser.getSelectedNamedGroup() },
                    new ECPointFormat[] { ECPointFormat.UNCOMPRESSED }, stream);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }
    }

    protected void computePremasterSecret(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) {
        premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(publicKey, privateKey);
    }

    protected void preparePublicKeyBaseX(T msg, ECPoint clientPublicKey) {
        msg.setPublicKeyBaseX(clientPublicKey.getRawXCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseX: " + msg.getPublicKeyBaseX().getValue());
    }

    protected void preparePublicKeyBaseY(T msg, ECPoint clientPublicKey) {
        msg.setPublicKeyBaseY(clientPublicKey.getRawYCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseY: " + msg.getPublicKeyBaseY().getValue());
    }

    protected void prepareEcPointFormat(T msg) {
        msg.setEcPointFormat(serializedPoint[0]);
        LOGGER.debug("EcPointFormat: " + msg.getEcPointFormat().getValue());
    }

    protected void prepareEcPointEncoded(T msg) {
        msg.setEcPointEncoded(Arrays.copyOfRange(serializedPoint, 1, serializedPoint.length));
        LOGGER.debug("EcPointEncoded: " + ArrayConverter.bytesToHexString(msg.getEcPointEncoded().getValue()));
    }

    protected void prepareSerializedPublicKey(T msg) {
        msg.setPublicKey(serializedPoint);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getPublicKey().getValue()));
    }

    protected void prepareSerializedPublicKeyLength(T msg) {
        msg.setPublicKeyLength(msg.getPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getPublicKeyLength().getValue());
    }

    protected void preparePremasterSecret(T msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    protected void prepareClientRandom(T msg) {
        // TODO this is spooky
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientRandom(random);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    @Override
    public void prepareAfterParse() {
        try {
            msg.prepareComputations();
            List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            short[] pointFormats = ECCUtilsBCWrapper.convertPointFormats(formatArray);
            ECPublicKeyParameters clientPublicKey = TlsECCUtils.deserializeECPublicKey(pointFormats,
                    getDomainParameters(chooser.getEcCurveType(), chooser.getSelectedNamedGroup()), msg.getPublicKey()
                            .getValue());
            CustomECPoint customClientKey = new CustomECPoint(clientPublicKey.getQ().getRawXCoord().toBigInteger(),
                    clientPublicKey.getQ().getRawYCoord().toBigInteger());
            msg.getComputations().setClientPublicKey(customClientKey);

            BigInteger privatekey = chooser.getServerEcPrivateKey();
            computePremasterSecret(clientPublicKey,
                    new ECPrivateKeyParameters(privatekey, clientPublicKey.getParameters()));
            preparePremasterSecret(msg);
            prepareClientRandom(msg);
        } catch (IOException ex) {
            throw new PreparationException("Could prepare ECDHClientKeyExchange Message after Parse", ex);
        }
    }
}
