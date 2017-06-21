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
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
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

    private ECPublicKeyParameters serverEcPublicKey;
    private ECPrivateKeyParameters serverEcPrivateKey;
    private ECPublicKeyParameters clientEcPublicKey;
    private ECPrivateKeyParameters clientEcPrivateKey;
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
        msg.prepareComputations();
        AsymmetricCipherKeyPair kp = null;
        serverEcPublicKey = context.getServerEcPublicKeyParameters();
        if (hasServerPublicKeyParameters()) {
            kp = generateFreshKeyPair();
        } else {
            // The Server did not send a server key exchange message and we have
            // to extract
            // the ec publickey from the certificate
            serverEcPublicKey = createECPublicKeyParameters();
            kp = generatePublicKeyFromParameters(serverEcPublicKey);
        }

        clientEcPublicKey = (ECPublicKeyParameters) kp.getPublic();
        clientEcPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();

        // do some ec point modification
        preparePublicKeyBaseX(msg);
        preparePublicKeyBaseY(msg);

        ECCurve curve = clientEcPublicKey.getParameters().getCurve();
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
            computePremasterSecret(serverEcPublicKey, clientEcPrivateKey);
            preparePremasterSecret(msg);
            prepareClientRandom(msg);
            computeMasterSecret(premasterSecret, random);
            prepareMasterSecret(msg);
        } catch (IOException ex) {
            throw new PreparationException("EC point serialization failure", ex);
        }
    }

    private AsymmetricCipherKeyPair generateFreshKeyPair() {
        return TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), serverEcPublicKey.getParameters());
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

    private void computePremasterSecret(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) {
        premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(publicKey, privateKey);
    }

    private void computeMasterSecret(byte[] preMasterSecret, byte[] random) {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        masterSecret = PseudoRandomFunction.compute(prfAlgorithm, preMasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
    }

    private void preparePublicKeyBaseX(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyBaseX(clientEcPublicKey.getQ().getAffineXCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseX: " + msg.getPublicKeyBaseX().getValue());
    }

    private void preparePublicKeyBaseY(ECDHClientKeyExchangeMessage msg) {
        msg.setPublicKeyBaseY(clientEcPublicKey.getQ().getAffineYCoord().toBigInteger());
        LOGGER.debug("PublicKeyBaseY: " + msg.getPublicKeyBaseY().getValue());
    }

    private boolean hasServerPublicKeyParameters() {
        return serverEcPublicKey != null;
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
        random = context.getClientServerRandom();
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
            List<ECPointFormat> pointFormatList = context.getServerPointFormatsList();
            ECPointFormat[] formatArray = pointFormatList.toArray(new ECPointFormat[pointFormatList.size()]);
            short[] pointFormats = ECCUtilsBCWrapper.convertPointFormats(formatArray);
            clientEcPublicKey = TlsECCUtils.deserializeECPublicKey(pointFormats, context
                    .getServerEcPublicKeyParameters().getParameters(), msg.getSerializedPublicKey().getValue());
            serverEcPrivateKey = context.getServerEcPrivateKeyParameters();
            computePremasterSecret(clientEcPublicKey, serverEcPrivateKey);
            preparePremasterSecret(msg);
            prepareClientRandom(msg);
            computeMasterSecret(premasterSecret, random);
            prepareMasterSecret(msg);
        } catch (IOException ex) {
            throw new PreparationException("Could prepare ECDHClientKeyExchange Message after Parse", ex);
        }
    }
}
