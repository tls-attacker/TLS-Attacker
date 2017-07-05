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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.IOException;
import java.math.BigInteger;
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

    private DHPrivateKeyParameters serverDhPrivate;
    private DHPublicKeyParameters serverDhPublic;
    private AsymmetricCipherKeyPair kp;
    private DHParameters newParams;
    private DHPrivateKeyParameters clientDhPrivate;
    private DHPublicKeyParameters clientDhPublic;
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
        LOGGER.debug("Preparing DHClientExchangeMessage");
        kp = null;
        msg.prepareComputations();
        if (!isServerPkKnown()) {
            kp = getParamsFromCertificate();
        } else {
            kp = generateFreshParams();
        }

        serverDhPublic = (DHPublicKeyParameters) kp.getPublic();
        serverDhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

        prepareG(msg);
        prepareP(msg);
        prepareY(msg);
        prepareX(msg);

        // set the modified values of client's private and public parameters
        newParams = new DHParameters(msg.getP().getValue(), msg.getG().getValue());
        clientDhPrivate = new DHPrivateKeyParameters(msg.getComputations().getX().getValue(), newParams);
        premasterSecret = calculatePremasterSecret(clientDhPrivate, context.getServerDHParameters().getPublicKey());
        preparePremasterSecret(msg);

        serializedPublicKey = BigIntegers.asUnsignedByteArray(msg.getY().getValue());
        prepareSerializedPublicKey(msg);
        prepareSerializedPublicKeyLength(msg);
        prepareClientRandom(msg);
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

    private boolean isServerPkKnown() {
        return context.getServerDHParameters() != null;
    }

    private void prepareG(DHClientKeyExchangeMessage msg) {
        msg.setG(serverDhPublic.getParameters().getG());
        LOGGER.debug("G: " + msg.getG().getValue());
    }

    private void prepareP(DHClientKeyExchangeMessage msg) {
        msg.setP(serverDhPublic.getParameters().getP());
        LOGGER.debug("P: " + msg.getP().getValue());
    }

    private void prepareY(DHClientKeyExchangeMessage msg) {
        msg.setY(serverDhPublic.getY());
        LOGGER.debug("Y: " + msg.getY().getValue());
    }

    private void prepareX(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setX(serverDhPrivate.getX());
        LOGGER.debug("X: " + msg.getComputations().getX().getValue());
    }

    private void preparePremasterSecret(DHClientKeyExchangeMessage msg) {
        msg.getComputations().setPremasterSecret(premasterSecret);
        premasterSecret = msg.getComputations().getPremasterSecret().getValue();
        LOGGER.debug("PremasterSecret: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getPremasterSecret().getValue()));
    }

    private void prepareSerializedPublicKey(DHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKey(serializedPublicKey);
        LOGGER.debug("SerializedPublicKey: " + ArrayConverter.bytesToHexString(msg.getSerializedPublicKey().getValue()));
    }

    private void prepareSerializedPublicKeyLength(DHClientKeyExchangeMessage msg) {
        msg.setSerializedPublicKeyLength(msg.getSerializedPublicKey().getValue().length);
        LOGGER.debug("SerializedPublicKeyLenth: " + msg.getSerializedPublicKeyLength().getValue());
    }

    private void prepareClientRandom(DHClientKeyExchangeMessage msg) {
        random = context.getClientServerRandom();
        msg.getComputations().setClientRandom(random);
        random = msg.getComputations().getClientRandom().getValue();
        LOGGER.debug("ClientRandom: "
                + ArrayConverter.bytesToHexString(msg.getComputations().getClientRandom().getValue()));
    }

    @Override
    public void prepareAfterParse() {

        serverDhPrivate = context.getServerDhPrivateKeyParameters();
        clientDhPublic = new DHPublicKeyParameters(new BigInteger(msg.getSerializedPublicKey().getValue()), context
                .getServerDHParameters().getPublicKey().getParameters());
        msg.prepareComputations();
        premasterSecret = calculatePremasterSecret(serverDhPrivate, clientDhPublic);
        preparePremasterSecret(msg);
        prepareClientRandom(msg);
    }
}
