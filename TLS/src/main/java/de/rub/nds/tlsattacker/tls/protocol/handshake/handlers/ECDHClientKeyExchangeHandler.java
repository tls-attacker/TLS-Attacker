/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.crypto.ECCUtilsBCWrapper;
import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ECDHClientKeyExchangeHandler extends ClientKeyExchangeHandler<ECDHClientKeyExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger(ECDHClientKeyExchangeHandler.class);

    public ECDHClientKeyExchangeHandler(TlsContext tlsContext) {
	super(tlsContext);
	this.correctProtocolMessageClass = ECDHClientKeyExchangeMessage.class;
	this.keyExchangeAlgorithm = KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
	if (tlsContext.getEcContext().getServerPublicKeyParameters() == null) {
	    // we are probably handling a simple ECDH ciphersuite, we try to
	    // establish server public key parameters from the server
	    // certificate message
	    Certificate x509Cert = tlsContext.getServerCertificate();

	    SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
	    ECPublicKeyParameters parameters;
	    try {
		parameters = (ECPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
		ECPublicKeyParameters publicKeyParameters = (ECPublicKeyParameters) parameters;
		tlsContext.getEcContext().setServerPublicKeyParameters(parameters);
		LOGGER.debug("Parsed the following EC domain parameters from the certificate: ");
		LOGGER.debug("  Curve order: {}", publicKeyParameters.getParameters().getCurve().getOrder());
		LOGGER.debug("  Parameter A: {}", publicKeyParameters.getParameters().getCurve().getA());
		LOGGER.debug("  Parameter B: {}", publicKeyParameters.getParameters().getCurve().getB());
		LOGGER.debug("  Base point: {} ", publicKeyParameters.getParameters().getG());
		LOGGER.debug("  Public key point Q: {} ", publicKeyParameters.getQ());
	    } catch (IOException e) {
		throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate", e);
	    }
	}

	AsymmetricCipherKeyPair kp = TlsECCUtils.generateECKeyPair(new SecureRandom(), tlsContext.getEcContext()
		.getServerPublicKeyParameters().getParameters());

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

	try {
	    byte[] serializedPoint = ECCUtilsBCWrapper.serializeECPoint(pointFormats, point);
	    protocolMessage.setEcPointFormat(serializedPoint[0]);
	    protocolMessage.setEcPointEncoded(Arrays.copyOfRange(serializedPoint, 1, serializedPoint.length));
	    protocolMessage.setPublicKeyLength(serializedPoint.length);

	    byte[] result = ArrayConverter.concatenate(new byte[] { protocolMessage.getPublicKeyLength().getValue()
		    .byteValue() }, new byte[] { protocolMessage.getEcPointFormat().getValue() }, protocolMessage
		    .getEcPointEncoded().getValue());

	    byte[] premasterSecret = TlsECCUtils.calculateECDHBasicAgreement(tlsContext.getEcContext()
		    .getServerPublicKeyParameters(), ecPrivateKey);
	    byte[] random = tlsContext.getClientServerRandom();
	    protocolMessage.setPremasterSecret(premasterSecret);
	    LOGGER.debug("Computed PreMaster Secret: {}",
		    ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));
	    LOGGER.debug("Client Server Random: {}", ArrayConverter.bytesToHexString(random));

	    PRFAlgorithm prfAlgorithm = PRFAlgorithm.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		    tlsContext.getSelectedCipherSuite());
	    byte[] masterSecret = PseudoRandomFunction.compute(tlsContext.getProtocolVersion(), protocolMessage
		    .getPremasterSecret().getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random,
		    HandshakeByteLength.MASTER_SECRET, prfAlgorithm.getJavaName());
	    LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	    protocolMessage.setMasterSecret(masterSecret);
	    tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	    return result;

	} catch (IOException ex) {
	    throw new WorkflowExecutionException("EC point serialization failure", ex);
	}
    }

}
