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
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import java.io.ByteArrayInputStream;
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
 * @author Florian Linsner - florian.linsner@rub.de
 */
public class PskEcDhClientKeyExchangePreparator extends
        ECDHClientKeyExchangePreparator<PskEcDhClientKeyExchangeMessage> {

    private ByteArrayOutputStream outputStream;
    private byte[] ecdhValue;
    private final PskEcDhClientKeyExchangeMessage msg;

    public PskEcDhClientKeyExchangePreparator(Chooser chooser, PskEcDhClientKeyExchangeMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        msg.setIdentity(chooser.getPSKIdentity());
        msg.setIdentityLength(msg.getIdentity().getValue().length);
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
            ecdhValue = TlsECCUtils.calculateECDHBasicAgreement(
                    new ECPublicKeyParameters(ecParams.getCurve().createPoint(
                            msg.getComputations().getServerPublicKeyX().getValue(),
                            msg.getComputations().getServerPublicKeyY().getValue()), ecParams),
                    new ECPrivateKeyParameters(privateKey, ecParams));
        } catch (IllegalArgumentException E) {
            ecdhValue = chooser.getPreMasterSecret();
        }
        premasterSecret = generatePremasterSecret(ecdhValue);
        preparePremasterSecret(msg);
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
    }

    private void computeECDHValue(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) {
        ecdhValue = TlsECCUtils.calculateECDHBasicAgreement(publicKey, privateKey);
    }

    private byte[] generatePremasterSecret(byte[] ecdhValue) {

        outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(ArrayConverter.intToBytes(ecdhValue.length, HandshakeByteLength.PSK_LENGTH));
            LOGGER.debug("PremasterSecret: dhValue Length: " + ecdhValue.length);
            outputStream.write(ecdhValue);
            LOGGER.debug("PremasterSecret: dhValue" + ecdhValue);
            outputStream.write(ArrayConverter.intToBytes(chooser.getConfig().getDefaultPSKKey().length,
                    HandshakeByteLength.PSK_LENGTH));
            outputStream.write(chooser.getConfig().getDefaultPSKKey());
        } catch (IOException ex) {
            LOGGER.warn("Encountered exception while writing to ByteArrayOutputStream.");
            LOGGER.debug(ex);
        }
        byte[] tempPremasterSecret = outputStream.toByteArray();
        LOGGER.debug("PremasterSecret: " + tempPremasterSecret);
        return tempPremasterSecret;
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
            computeECDHValue(clientPublicKey, new ECPrivateKeyParameters(privatekey, clientPublicKey.getParameters()));
            premasterSecret = generatePremasterSecret(ecdhValue);
            preparePremasterSecret(msg);
            prepareClientRandom(msg);
        } catch (IOException ex) {
            throw new PreparationException("Could prepare PSKECDHClientKeyExchange Message after Parse", ex);
        }
    }
}
