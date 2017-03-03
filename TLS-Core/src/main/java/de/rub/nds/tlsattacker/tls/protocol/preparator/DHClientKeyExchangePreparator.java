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
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.*;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.RandomKeyGeneratorHelper;
import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.ServerDHParams;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.BigIntegers;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class DHClientKeyExchangePreparator extends ClientKeyExchangePreparator<DHClientKeyExchangeMessage> {

    private final DHClientKeyExchangeMessage message;
    
    public DHClientKeyExchangePreparator(TlsContext context, DHClientKeyExchangeMessage message) {
        super(context, message);
        this.message = message;
    }
    
    @Override
    public void prepare() {
        AsymmetricCipherKeyPair kp = null;
        byte[] premasterSecret = null;
        if (context.getServerDHParameters() == null) {
            Certificate x509Cert = context.getServerCertificate();
            SubjectPublicKeyInfo keyInfo = x509Cert.getCertificateAt(0).getSubjectPublicKeyInfo();
            DHPublicKeyParameters parameters = null;
            if (!keyInfo.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.dhpublicnumber)) {
                if (context.getConfig().isFuzzingMode()) {
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
                    kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(),
                            context.getServerDHParameters()
                                    .getPublicKey().getParameters());
                } catch (IOException e) {
                    throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate",
                            e);
                }
            }
            context.setServerDHParameters(new ServerDHParams(parameters));

        } else {
            try {
                kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(),//TODO use badrandom
                        context.getServerDHParameters().getPublicKey()
                                .getParameters());

            } catch (IllegalArgumentException E) {
                throw new UnsupportedOperationException(E);
            }
        }

        DHPublicKeyParameters dhPublic = (DHPublicKeyParameters) kp.getPublic();
        DHPrivateKeyParameters dhPrivate = (DHPrivateKeyParameters) kp.getPrivate();

        message.setG(dhPublic.getParameters().getG());
        message.setP(dhPublic.getParameters().getP());
        message.setY(dhPublic.getY());
        message.setX(dhPrivate.getX());

        // set the modified values of client's private and public parameters
        DHParameters newParams = new DHParameters(message.getP().getValue(),
                message.getG().getValue());
        // DHPublicKeyParameters newDhPublic = new
        // DHPublicKeyParameters(dhMessage.getY().getValue(), newParams);
        DHPrivateKeyParameters newDhPrivate = new DHPrivateKeyParameters(message.getX().getValue(), newParams);
        try {
            premasterSecret
                    = TlsDHUtils.calculateDHBasicAgreement(context.getServerDHParameters().getPublicKey(),
                            newDhPrivate);
        } catch (IllegalArgumentException e) {
            if (context.getConfig().isFuzzingMode()) {
                premasterSecret = TlsDHUtils.calculateDHBasicAgreement(dhPublic,
                        dhPrivate);
            } else {
                throw new IllegalArgumentException(e);
            }
        }
        message.setPremasterSecret(premasterSecret);
        byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(message.getY().getValue());
        message.setSerializedPublicKey(serializedPublicKey);
        message.setSerializedPublicKeyLength(message.getSerializedPublicKey().getValue().length);


        byte[] random = context.getClientServerRandom();

        PRFAlgorithm prfAlgorithm
                = AlgorithmResolver.getPRFAlgorithm(context.getSelectedProtocolVersion(),
                        context.getSelectedCipherSuite());
        byte[] masterSecret = PseudoRandomFunction.compute(prfAlgorithm,
                message.getPremasterSecret()
                        .getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random,
                HandshakeByteLength.MASTER_SECRET);
        message.setMasterSecret(masterSecret);
        context.setMasterSecret(message.getMasterSecret().getValue());
    }

}
