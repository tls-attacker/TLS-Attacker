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
import java.util.Arrays;
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

    private DHPrivateKeyParameters dhPrivate;
    private DHPublicKeyParameters dhPublic;
    private AsymmetricCipherKeyPair kp;
    private DHParameters newParams;
    private DHPrivateKeyParameters newDhPrivate;
    private byte[] premasterSecret;
    private byte[] serializedPublicKey;
    private byte[] random;
    private byte[] masterSecret;
    private final DHClientKeyExchangeMessage msg;

    public DHClientKeyExchangePreparator(TlsContext context, DHClientKeyExchangeMessage msg) {
        super(context, msg);
        this.msg = msg;
    }

    @Override
    public void prepareHandshakeMessageContents() {
        kp = null;

        if (!hasServerPublicKey()) {
            kp = getParamsFromCertificate();

        } else {
            kp = generateFreshParams();
        }

        dhPublic = (DHPublicKeyParameters) kp.getPublic();
        dhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

        prepareG(msg);
        prepareP(msg);
        prepareY(msg);
        prepareX(msg);

        // set the modified values of client's private and public parameters
        newParams = new DHParameters(msg.getP().getValue(), msg.getG().getValue());
        newDhPrivate = new DHPrivateKeyParameters(msg.getComputations().getX().getValue(), newParams);

        preparePremasterSecret(msg);

        serializedPublicKey = BigIntegers.asUnsignedByteArray(msg.getY().getValue());
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);

        prepareClientRandom(msg);

        prepareMasterSecret(msg);
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
        masterSecret = PseudoRandomFunction.compute(prfAlgorithm, premasterSecret,
                PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        return masterSecret;

    }

    private boolean hasServerPublicKey() {
        return context.getServerPublicKey() == null;
    }

    private void prepareG(DHClientKeyExchangeMessage msg) {
        msg.setG(dhPublic.getParameters().getG());
        LOGGER.debug("G: " + msg.getG().getValue());
    }

    private void prepareP(DHClientKeyExchangeMessage msg) {
        msg.setP(dhPublic.getParameters().getP());
        LOGGER.debug("P: " + msg.getP().getValue());
    }

    private void prepareY(DHClientKeyExchangeMessage msg) {
        msg.setY(dhPublic.getY());
        LOGGER.debug("Y: " + msg.getY().getValue());
    }

    private void prepareX(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setX(dhPrivate.getX());
        LOGGER.debug("X: " + msg.getComputations().getX().getValue());
    }

    private void preparePremasterSecret(DHClientKeyExchangeMessage msg) {
        premasterSecret = calculatePremasterSecret(newDhPrivate, context.getServerDHParameters().getPublicKey());
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: " + Arrays.toString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareSerializedPublicKey(DHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(serializedPublicKey);
        LOGGER.debug("SerializedPublicKey: " + Arrays.toString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(DHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLenth: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void prepareClientRandom(DHClientKeyExchangeMessage msg) {
        random = context.getClientServerRandom();
        msg.getComputations().setClientRandom(random);
        random = msg.getComputations().getClientRandom().getValue();
        LOGGER.debug("ClientRandom: " + Arrays.toString(msg.getComputations().getClientRandom().getValue()));
    }

    private void prepareMasterSecret(DHClientKeyExchangeMessage msg) {
        masterSecret = calculateMasterSecret(random, premasterSecret);
        msg.getComputations().setMasterSecret(masterSecret);
        LOGGER.debug("MasterSecret: " + Arrays.toString(msg.getComputations().getMasterSecret().getValue()));
    }
}
