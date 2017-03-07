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

    private static final Logger LOGGER = LogManager.getLogger(ECDHClientKeyExchangeMessage.class);

    private final ECDHClientKeyExchangeMessage message;

    public ECDHClientKeyExchangePreparator(TlsContext context, ECDHClientKeyExchangeMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        AsymmetricCipherKeyPair kp = null;
        if (context.getServerPublicKeyParameters() == null) {
            kp = generateKeyPairFromCertificate();
        } else {
            kp = generateFreshKeyPair();
        }

        ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters) kp.getPublic();
        ECPrivateKeyParameters ecPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();

        // do some ec point modification
        message.setPublicKeyBaseX(ecPublicKey.getQ().getAffineXCoord().toBigInteger());
        message.setPublicKeyBaseY(ecPublicKey.getQ().getAffineYCoord().toBigInteger());

        ECCurve curve = ecPublicKey.getParameters().getCurve();
        ECPoint point = curve.createPoint(message.getPublicKeyBaseX().getValue(), message.getPublicKeyBaseY()
                .getValue());

        ECPointFormat[] pointFormats = context.getServerPointFormats();
        // TODO i guess some of the intermediate calculated values could be
        // inseterd into computations
        try {
            byte[] serializedPoint = ECCUtilsBCWrapper.serializeECPoint(pointFormats, point);
            message.setEcPointFormat(serializedPoint[0]);
            message.setEcPointEncoded(Arrays.copyOfRange(serializedPoint, 1, serializedPoint.length));
            message.setSerializedPublicKey(serializedPoint);
            message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);

            byte[] result = ArrayConverter.concatenate(new byte[] { message.getSerializedPublicKeyLength().getValue()
                    .byteValue() }, new byte[] { message.getEcPointFormat().getValue() }, message.getEcPointEncoded()
                    .getValue());

            byte[] premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(context.getServerPublicKeyParameters(),
                    ecPrivateKey);
            message.getComputations().setPremasterSecret(premasterSecret);

            byte[] random = context.getClientServerRandom();
            message.getComputations().setClientRandom(random);

            byte[] masterSecret = computeMasterSecret(message.getComputations().getPremasterSecret().getValue(),
                    message.getComputations().getClientRandom().getValue());
            message.getComputations().setMasterSecret(masterSecret);
        } catch (IOException ex) {
            throw new PreparationException("EC point serialization failure", ex);
        }
    }

    private AsymmetricCipherKeyPair generateFreshKeyPair() {
        return TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), context.getServerPublicKeyParameters()
                .getParameters());
    }

    private AsymmetricCipherKeyPair generateKeyPairFromCertificate() {
        Certificate x509Cert = context.getServerCertificate();
        SubjectPublicKeyInfo keyInfo = x509Cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)) {
            throw new PreparationException("Invalid KeyType in ServerCertificate");
        } else {
            try {
                ECPublicKeyParameters parameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
                return TlsECCUtils.generateECKeyPair(RandomHelper.getBadSecureRandom(), parameters.getParameters());
            } catch (IOException e) {
                throw new PreparationException("Problem in parsing public key parameters from certificate", e);
            }
        }
    }

    private byte[] computeMasterSecret(byte[] preMasterSecret, byte[] random) {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        return PseudoRandomFunction.compute(prfAlgorithm, preMasterSecret, PseudoRandomFunction.MASTER_SECRET_LABEL,
                random, HandshakeByteLength.MASTER_SECRET);
    }
}
