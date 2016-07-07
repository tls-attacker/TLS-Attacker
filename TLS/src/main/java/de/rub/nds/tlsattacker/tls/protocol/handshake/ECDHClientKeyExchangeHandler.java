/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomKeyGeneratorHelper;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage>
{

    private static final Logger LOGGER = LogManager.getLogger(ECDHClientKeyExchangeHandler.class);

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext)
    {
        super(tlsContext);
        this.correctProtocolMessageClass = ECDHClientKeyExchangeMessage.class;
        this.keyExchangeAlgorithm = KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
    }

    @Override
    public int parseKeyExchangeMessage(byte[] message, int pointer)
    {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    byte[] prepareKeyExchangeMessage()
    {
        ECPublicKeyParameters parameters = null;
        AsymmetricCipherKeyPair kp = null;
        if (tlsContext.getEcContext().getServerPublicKeyParameters() == null)
        {
            // we are probably handling a simple ECDH ciphersuite, we try to
            // establish server public key parameters from the server
            // certificate message
            Certificate x509Cert = tlsContext.getServerCertificate();

            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();

            if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey))
            {
                if (protocolMessage.isFuzzingMode())
                {
                    kp = RandomKeyGeneratorHelper.generateECPublicKey();
                    parameters = (ECPublicKeyParameters) kp.getPublic();
                    LOGGER.debug("Generating EC domain parameters on the fly: ");
                }
                else
                {
                    throw new WorkflowExecutionException("Invalid KeyType, not in FuzzingMode so no Keys are generated on the fly");
                }
            }
            else
            {
                try
                {
                    parameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
                    kp = TlsECCUtils.generateECKeyPair(new SecureRandom(), tlsContext.getEcContext()
                            .getServerPublicKeyParameters().getParameters());

                }
                catch (NoSuchMethodError e)
                {
                    LOGGER.debug("The method was not found. It is possible that it is because an older bouncy castle"
                            + " library was used. We try to proceed the workflow.", e);
                }
                catch (IOException e)
                {
                    throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate", e);
                }
            }
            tlsContext.getEcContext().setServerPublicKeyParameters(parameters);
            LOGGER.debug("Parsed the following EC domain parameters from the certificate: ");
            LOGGER.debug("  Curve order: {}", parameters.getParameters().getCurve().getOrder());
            LOGGER.debug("  Parameter A: {}", parameters.getParameters().getCurve().getA());
            LOGGER.debug("  Parameter B: {}", parameters.getParameters().getCurve().getB());
            LOGGER.debug("  Base point: {} ", parameters.getParameters().getG());
            LOGGER.debug("  Public key point Q: {} ", parameters.getQ());
        }
        else
        {
            kp = TlsECCUtils.generateECKeyPair(new SecureRandom(), tlsContext.getEcContext()
                            .getServerPublicKeyParameters().getParameters());
        }

        ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters) kp.getPublic();
        ECPrivateKeyParameters ecPrivateKey = (ECPrivateKeyParameters) kp.getPrivate();

        // do some ec point modification
        protocolMessage.setPublicKeyBaseX(ecPublicKey.getQ().getAffineXCoord().toBigInteger());
        protocolMessage.setPublicKeyBaseY(ecPublicKey.getQ().getAffineYCoord().toBigInteger());

        ECCurve curve = ecPublicKey.getParameters().getCurve();
        ECPoint point = curve.createPoint(protocolMessage.getPublicKeyBaseX().getValue(), protocolMessage
                .getPublicKeyBaseY().getValue());

        LOGGER.debug("Using the following point:");
        LOGGER.debug("X: " + protocolMessage.getPublicKeyBaseX().getValue().toString());
        LOGGER.debug("Y: " + protocolMessage.getPublicKeyBaseY().getValue().toString());

        // System.out.println("-----------------\nUsing the following point:");
        // System.out.println("X: " + point.getAffineXCoord());
        // System.out.println("Y: " + point.getAffineYCoord());
        // System.out.println("-----------------\n");
        ECPointFormat[] pointFormats = tlsContext.getEcContext().getServerPointFormats();

        try
        {
            byte[] serializedPoint = ECCUtilsBCWrapper.serializeECPoint(pointFormats, point);
            protocolMessage.setEcPointFormat(serializedPoint[0]);
            protocolMessage.setEcPointEncoded(Arrays.copyOfRange(serializedPoint, 1, serializedPoint.length));
            protocolMessage.setPublicKeyLength(serializedPoint.length);

            byte[] result = ArrayConverter.concatenate(new byte[]
            {
                protocolMessage.getPublicKeyLength().getValue()
                .byteValue()
            }, new byte[]
            {
                protocolMessage.getEcPointFormat().getValue()
            }, protocolMessage
                    .getEcPointEncoded().getValue());

            byte[] premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(tlsContext.getEcContext()
                    .getServerPublicKeyParameters(), ecPrivateKey);
            byte[] random = tlsContext.getClientServerRandom();
            protocolMessage.setPremasterSecret(premasterSecret);
            LOGGER.debug("Computed PreMaster Secret: {}",
                    ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));
            LOGGER.debug("Client Server Random: {}", ArrayConverter.bytesToHexString(random));

            PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(tlsContext.getProtocolVersion(),
                    tlsContext.getSelectedCipherSuite());
            byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm, protocolMessage.getPremasterSecret()
                    .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random, HandshakeByteLength.MASTER_SECRET);
            LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

            protocolMessage.setMasterSecret(masterSecret);
            tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

            return result;

        }
        catch (IOException ex)
        {
            throw new WorkflowExecutionException("EC point serialization failure", ex);
        }
    }

}
