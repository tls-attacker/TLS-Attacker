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
        LOGGER.debug("Preparing ECDHClientExchangeMessage");
        prepareAfterParse(true);
        prepareEcdhParams();
    }

    protected ECDomainParameters getDomainParameters(EllipticCurveType curveType, NamedGroup namedGroup) {
        InputStream stream = new ByteArrayInputStream(ArrayConverter.concatenate(new byte[] { curveType.getValue() },
                namedGroup.getValue()));
        try {
            return ECCUtilsBCWrapper.readECParameters(new NamedGroup[] { namedGroup },
                    new ECPointFormat[] { ECPointFormat.UNCOMPRESSED }, stream);
        } catch (IOException ex) {
            throw new PreparationException("Failed to generate EC domain parameters", ex);
        }
    }

    protected byte[] computePremasterSecret(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) {
        return TlsECCUtils.calculateECDHBasicAgreement(publicKey, privateKey);
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
        msg.setPublicKey(ArrayConverter.concatenate(new byte[] { msg.getEcPointFormat().getValue() }, msg
                .getEcPointEncoded().getValue()));
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

    protected void prepareClientServerRandom(T msg) {
        random = ArrayConverter.concatenate(chooser.getClientRandom(), chooser.getServerRandom());
        msg.getComputations().setClientServerRandom(random);
        LOGGER.debug("ClientServerRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientServerRandom().getValue()));
    }

    @Override
    public void prepareAfterParse(boolean clientMode) {
        msg.prepareComputations();
        prepareClientServerRandom(msg);
        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        LOGGER.debug("Used Group: " + usedGroup.name());
        setComputationPrivateKey(msg, clientMode);
        ECDomainParameters ecParams = getDomainParameters(chooser.getEcCurveType(), usedGroup);
        if (clientMode) {
            ECPoint clientPublicKey = ecParams.getG().multiply(msg.getComputations().getPrivateKey().getValue());
            clientPublicKey = clientPublicKey.normalize();
            if (clientPublicKey.getRawXCoord() != null && clientPublicKey.getRawYCoord() != null) {
                msg.getComputations().setComputedPublicKeyX(clientPublicKey.getRawXCoord().toBigInteger());
                msg.getComputations().setComputedPublicKeyY(clientPublicKey.getRawYCoord().toBigInteger());
            } else {
                LOGGER.warn("Could not compute correct public key. Using empty one instead");
                msg.getComputations().setComputedPublicKeyX(BigInteger.ZERO);
                msg.getComputations().setComputedPublicKeyY(BigInteger.ZERO);
            }
        }
        setComputationPublicKey(msg, clientMode);

        LOGGER.debug("PublicKey used:" + msg.getComputations().getPublicKey().toString());
        LOGGER.debug("PrivateKey used:" + msg.getComputations().getPrivateKey().getValue());
        ECPoint publicKey = ecParams.getCurve().createPoint(msg.getComputations().getPublicKey().getX(),
                msg.getComputations().getPublicKey().getY());
        publicKey = publicKey.normalize();
        premasterSecret = computePremasterSecret(new ECPublicKeyParameters(publicKey, ecParams),
                new ECPrivateKeyParameters(msg.getComputations().getPrivateKey().getValue(), ecParams));
        preparePremasterSecret(msg);
    }

    private void prepareEcdhParams() {
        // Encode the public key in the computations
        List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
        ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);

        NamedGroup usedGroup = chooser.getSelectedNamedGroup();
        ECDomainParameters ecParams = getDomainParameters(chooser.getEcCurveType(), usedGroup);
        ECPoint publicKey = ecParams.getCurve().createPoint(msg.getComputations().getComputedPublicKeyX().getValue(),
                msg.getComputations().getComputedPublicKeyY().getValue());
        try {
            serializedPoint = ECCUtilsBCWrapper.serializeECPoint(formatArray, publicKey);
        } catch (IOException ex) {
            throw new PreparationException("Could not serialize clientPublicKey", ex);
        }
        prepareEcPointFormat(msg);
        prepareEcPointEncoded(msg);
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
    }

    protected void setComputationPrivateKey(T msg, boolean clientMode) {
        if (clientMode) {
            msg.getComputations().setPrivateKey(chooser.getClientEcPrivateKey());
        } else {
            msg.getComputations().setPrivateKey(chooser.getServerEcPrivateKey());
        }
        LOGGER.debug("Computation PrivateKey: " + msg.getComputations().getPrivateKey().getValue().toString());
    }

    protected void setComputationPublicKey(T msg, boolean clientMode) {
        if (clientMode) {
            msg.getComputations().setPublicKey(chooser.getServerEcPublicKey().getX(),
                    chooser.getServerEcPublicKey().getY());
        } else {
            serializedPoint = msg.getPublicKey().getValue();
            List<ECPointFormat> pointFormatList = chooser.getServerSupportedPointFormats();
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            NamedGroup usedGroup = chooser.getSelectedNamedGroup();
            ECDomainParameters ecParams = getDomainParameters(chooser.getEcCurveType(), usedGroup);
            short[] pointFormats = ECCUtilsBCWrapper.convertPointFormats(formatArray);
            try {
                ECPublicKeyParameters clientPublicKey = TlsECCUtils.deserializeECPublicKey(pointFormats, ecParams,
                        serializedPoint);
                msg.getComputations().setPublicKey(clientPublicKey.getQ().getRawXCoord().toBigInteger(),
                        clientPublicKey.getQ().getRawYCoord().toBigInteger());
            } catch (IOException ex) {
                throw new PreparationException("Could not deserialize EC Point: "
                        + ArrayConverter.bytesToHexString(serializedPoint), ex);
            }
        }
        LOGGER.debug("Computation PublicKey: " + msg.getComputations().getPublicKey().toString());

    }

}
