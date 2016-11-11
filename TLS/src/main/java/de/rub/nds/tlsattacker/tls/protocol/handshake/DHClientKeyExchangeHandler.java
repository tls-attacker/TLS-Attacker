/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomKeyGeneratorHelper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 * Handler for DH and DHE ClientKeyExchange messages
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class DHClientKeyExchangeHandler extends ClientKeyExchangeHandler<DHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(DHClientKeyExchangeHandler.class);

    public DHClientKeyExchangeHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = DHClientKeyExchangeMessage.class;
        this.keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(tlsContext.getSelectedCipherSuite());
    }

    @Override
    public int parseKeyExchangeMessage(byte[] message, int currentPointer) {
        int nextPointer = currentPointer + HandshakeByteLength.DH_PARAM_LENGTH;
        int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setSerializedPublicKeyLength(length);
        currentPointer = nextPointer;

        nextPointer = currentPointer + length;
        protocolMessage.setSerializedPublicKey(Arrays.copyOfRange(message, currentPointer, nextPointer));
        BigInteger publicKey = new BigInteger(1, Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setY(publicKey);

        byte[] premasterSecret;

        DHPublicKeyParameters clientPubParameters = new DHPublicKeyParameters(protocolMessage.getY().getValue(),
                tlsContext.getServerDHParameters().getPublicKey().getParameters());

        premasterSecret = TlsDHUtils.calculateDHBasicAgreement(clientPubParameters,
                tlsContext.getServerDHPrivateKeyParameters());

        LOGGER.debug("Resulting premaster secret: {}", ArrayConverter.bytesToHexString(premasterSecret));

        protocolMessage.setPremasterSecret(premasterSecret);

        byte[] random = tlsContext.getClientServerRandom();

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
                .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        protocolMessage.setMasterSecret(masterSecret);
        LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

        tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

        currentPointer = nextPointer;

        return currentPointer;
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
        AsymmetricCipherKeyPair kp = null;
        byte[] premasterSecret = null;
        if (tlsContext.getServerDHParameters() == null) {
            // we are probably handling a simple DH ciphersuite, we try to
            // establish server public key parameters from the server
            // certificate message
            Certificate x509Cert = tlsContext.getServerCertificate();

            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
            DHPublicKeyParameters parameters;
            if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber)) {
                if (protocolMessage.isFuzzingMode()) {
                    kp = RandomKeyGeneratorHelper.generateDHPublicKey();
                    parameters = (DHPublicKeyParameters) kp.getPublic();
                } else {
                    throw new WorkflowExecutionException(
                            "Invalid KeyType, not in FuzzingMode so no Keys are generated on the fly");
                }
            } else {
                try {
                    // generate client's original dh public and private key,
                    // based on
                    // the
                    // server's public parameters
                    parameters = (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
                    kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(), tlsContext.getServerDHParameters()
                            .getPublicKey().getParameters());
                } catch (IOException e) {
                    throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate", e);
                }
            }
            tlsContext.setServerDHParameters(new ServerDHParams(parameters));

        } else {
            try {
                kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(), tlsContext.getServerDHParameters().getPublicKey()
                        .getParameters());

            } catch (IllegalArgumentException E) {
                throw new UnsupportedOperationException(E);
            }
        }

        DHPublicKeyParameters dhPublic = (DHPublicKeyParameters) kp.getPublic();
        DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

        protocolMessage.setG(dhPublic.getParameters().getG());
        protocolMessage.setP(dhPublic.getParameters().getP());
        protocolMessage.setY(dhPublic.getY());
        protocolMessage.setX(dhPrivate.getX());

        // set the modified values of client's private and public parameters
        DHParameters newParams = new DHParameters(protocolMessage.getP().getValue(), protocolMessage.getG().getValue());
        // DHPublicKeyParameters newDhPublic = new
        // DHPublicKeyParameters(dhMessage.getY().getValue(), newParams);
        DHPrivateKeyParameters newDhPrivate = new DHPrivateKeyParameters(protocolMessage.getX().getValue(), newParams);
        try {
            premasterSecret = TlsDHUtils.calculateDHBasicAgreement(tlsContext.getServerDHParameters().getPublicKey(),
                    newDhPrivate);
        } catch (IllegalArgumentException e) {
            if (protocolMessage.isFuzzingMode()) {
                premasterSecret = TlsDHUtils.calculateDHBasicAgreement(dhPublic, dhPrivate);
            } else {
                throw new IllegalArgumentException(e);
            }
        }
        protocolMessage.setPremasterSecret(premasterSecret);
        LOGGER.debug("Computed PreMaster Secret: {}",
                ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));

        byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(protocolMessage.getY().getValue());
        protocolMessage.setSerializedPublicKey(serializedPublicKey);
        protocolMessage.setSerializedPublicKeyLength(protocolMessage.getSerializedPublicKey().getValue().length);

        byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
                .getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage
                .getSerializedPublicKey().getValue());

        byte[] random = tlsContext.getClientServerRandom();

        PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
                tlsContext.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
                .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
        LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

        protocolMessage.setMasterSecret(masterSecret);
        tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

        return result;

    }
}
