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
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.PreparationException;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.RandomHelper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.interfaces.DHPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangePreparator extends ClientKeyExchangePreparator<DHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger("PREPARATOR");

    private final DHClientKeyExchangeMessage message;

    public DHClientKeyExchangePreparator(TlsContext context, DHClientKeyExchangeMessage message) {
        super(context, message);
        this.message = message;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        AsymmetricCipherKeyPair kp = null;

        if (context.getServerPublicKey() == null) {
            kp = getParamsFromCertificate();

        } else {
            kp = generateFreshParams();
        }

        DHPublicKeyParameters dhPublic = (DHPublicKeyParameters) kp.getPublic();
        DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

        message.setG(dhPublic.getParameters().getG());
        message.setP(dhPublic.getParameters().getP());
        message.setY(dhPublic.getY());
        message.getComputations().setX(dhPrivate.getX());

        // set the modified values of client's private and public parameters
        DHParameters newParams = new DHParameters(message.getP().getValue(), message.getG().getValue());
        DHPrivateKeyParameters newDhPrivate = new DHPrivateKeyParameters(message.getComputations().getX().getValue(),
                newParams);

        byte[] premasterSecret = calculatePremasterSecret(newDhPrivate, context.getServerDHParameters().getPublicKey());
        message.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = message.getComputations().getPremasterSecret().getValue();

        byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(message.getY().getValue());
        message.setSerializedPublicKey(serializedPublicKey);
        message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);

        byte[] random = context.getClientServerRandom();
        message.getComputations().setClientRandom(random);
        random = message.getComputations().getClientRandom().getValue();

        byte[] masterSecret = calculateMasterSecret(random, premasterSecret);
        message.getComputations().setMasterSecret(masterSecret);
    }

    private AsymmetricCipherKeyPair getParamsFromCertificate() {
        Certificate x509Cert = context.getServerCertificate();
        SubjectPublicKeyInfo keyInfo = x509Cert.getCertificateAt(0).getSubjectPublicKeyInfo();
        if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber)) {
            throw new PreparationException(
                    "Could not prepare DHClientKeyExchangeMessage since the Server Certificate does not contain a DH PublicKey.");
        } else {
            try {
                DHPublicKeyParameters parameters = (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
                return TlsDHUtils.generateDHKeyPair(RandomHelper.getBadSecureRandom(), context.getServerDHParameters()
                        .getPublicKey().getParameters());
            } catch (IOException e) {
                throw new PreparationException("Problem in parsing public key parameters from certificate", e);
            }
        }

    }

    private AsymmetricCipherKeyPair generateFreshParams() {
        try {
            return TlsDHUtils.generateDHKeyPair(RandomHelper.getBadSecureRandom(), context.getServerDHParameters()
                    .getPublicKey().getParameters());

        } catch (IllegalArgumentException E) {
            throw new PreparationException("Could not generate fresh DHParameters", E);
        }
    }

    private byte[] calculatePremasterSecret(DHPrivateKeyParameters dhPrivate, DHPublicKeyParameters dhPublic) {
        try {
            return TlsDHUtils.calculateDHBasicAgreement(dhPublic, dhPrivate);
        } catch (IllegalArgumentException e) {
            throw new PreparationException("Could not calculate PremasterSecret");
        }

    }

    private byte[] calculateMasterSecret(byte[] random, byte[] premasterSecret) {
        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                context.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, premasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        return masterSecret;

    }
}
