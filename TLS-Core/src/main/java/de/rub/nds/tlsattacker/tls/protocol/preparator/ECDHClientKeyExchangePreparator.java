/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.preparator;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ECDHClientKeyExchangePreparator extends ClientKeyExchangePreparator<ECDHClientKeyExchangeMessage> {

    private ECPublicKeyParameters ecPublicKey;
    private ECPrivateKeyParameters ecPrivateKey;
    private byte[] serializedPoint;
    private byte[] premasterSecret;
    private byte[] random;
    private byte[] masterSecret;
    private final ECDHClientKeyExchangeMessage msg;

    public ECDHClientKeyExchangePreparator(TlsContext context, ECDHClientKeyExchangeMessage message) {
        super(context, message);
        this.msg = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        AsymmetricCipherKeyPair kp = null;
        ECPublicKeyParameters parameters = context.getServerPublicKeyParameters();
        if (!hasServerPublicKeyParameters()) {
            parameters = createECPublicKeyParameters();
            kp = generatePublicKeyFromParameters(parameters);
        } else {
            kp = generateFreshKeyPair();
        }

        ecPublicKey = (ECPublicKeyParameters) kp.getPublic();
        ecPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();

        // do some ec point modification
        preparePublicKeyBaseX(msg);
        preparePublicKeyBaseY(msg);

        ECCurve curve = ecPublicKey.getParameters().getCurve();
        ECPoint point = curve.createPoint(msg.getPublicKeyBaseX().getValue(), msg.getPublicKeyBaseY().getValue());

        List<ECPointFormat> pointFormatList = context.getServerPointFormatsList();
        if (pointFormatList == null) {
            pointFormatList = new LinkedList<>();
            pointFormatList.add(ECPointFormat.UNCOMPRESSED);
        }
        // TODO i guess some of the intermediate calculated values could be
        // inserted into computations
        try {
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            serializedPoint = ECCUtilsBCWrapper.serializeECPoint(formatArray, point);
            prepareEcPointFormat(msg);
            prepareEcPointEncoded(msg);
            prepareSerializedPublicKey(msg);
            prepareSerializedPublicKeyLength(msg);

            // TODO this variable is never used
            byte[] result = ArrayConverter.concatenate(new byte[] { msg.getSerializedPublicKeyLength().getValue()
                    .byteValue() }, new byte[] { msg.getEcPointFormat().getValue() }, msg.getEcPointEncoded()
                    .getValue());

            premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(parameters, ecPrivateKey);
            preparePremasterSecret(msg);

            random = context.getClientServerRandom();
            prepareClientRandom(msg);

            masterSecret = computeMasterSecret(msg.getComputations().getPremasterSecret().getValue(), msg
                    .getComputations().getClientRandom().getValue());
            prepareMasterSecret(msg);
        } catch (IOException ex) {
            throw new PreparationException("EC point serialization failure", ex);
        }
    }

    private AsymmetricCipherKeyPair generateFreshKeyPair() {
        return TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), context.getServerPublicKeyParameters()
                .getParameters());
    }

    private ECPublicKeyParameters createECPublicKeyParameters() {
        Certificate x509Cert = context.getServerCertificate();
        SubjectPublicKeyInfo keyInfo = x509Cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            throw new PreparationException("Invalid KeyType in ServerCertificate");
        } else {
            try {
                return (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
            } catch (IOException e) {
                throw new PreparationException("Problem in parsing public key parameters from certificate", e);
            }
        }
    }

    private AsymmetricCipherKeyPair generatePublicKeyFromParameters(ECPublicKeyParameters parameters) {
        return TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), parameters.getParameters());
    }

    private byte[] computeMasterSecret(byte[] preMasterSecret, byte[] random) {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(prfAlgorithm, preMasterSecret, PseudoRandomFunction.MASTER_SECRET_LABEL,
                random, HandshakeByteLength.MASTER_SECRET);
    }

    private void preparePublicKeyBaseX(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyBaseX(ecPublicKey.getQ().getAffineXCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseX: " + msg.getPublicKeyBaseX().getValue());
    }

    private void preparePublicKeyBaseY(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyBaseY(ecPublicKey.getQ().getAffineYCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseY: " + msg.getPublicKeyBaseY().getValue());
    }

    private boolean hasServerPublicKeyParameters() {
        return context.getServerPublicKeyParameters() != null;
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
        msg.setSerializedPublicKey(serializedPoint);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(ECDHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLength: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void preparePremasterSecret(ECDHClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareClientRandom(ECDHClientKeyExchangeMessage msg) {
        msg.getComputations().setClientRandom(random);
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareMasterSecret(ECDHClientKeyExchangeMessage msg) {
        msg.getComputations().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getMasterSecret().getValue()));
    }
}
