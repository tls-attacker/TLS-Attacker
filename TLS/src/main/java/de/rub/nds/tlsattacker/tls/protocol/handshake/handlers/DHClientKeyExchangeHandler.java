/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.tls.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.tls.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.security.SecureRandom;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
	this.keyExchangeAlgorithm = KeyExchangeAlgorithm.getKeyExchangeAlgorithm(tlsContext.getSelectedCipherSuite());
    }

    @Override
    public int parseKeyExchangeMessage(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    byte[] prepareKeyExchangeMessage() {
	if (tlsContext.getServerDHParameters() == null) {
	    // we are probably handling a simple DH ciphersuite, we try to
	    // establish server public key parameters from the server
	    // certificate message
	    Certificate x509Cert = tlsContext.getServerCertificate();

	    SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
	    DHPublicKeyParameters parameters;
	    try {
		parameters = (DHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
		tlsContext.setServerDHParameters(new ServerDHParams(parameters));
	    } catch (IOException e) {
		throw new WorkflowExecutionException("Problem in parsing public key parameters from certificate", e);
	    }
	}

	// generate client's original dh public and private key, based on the
	// server's public parameters
	AsymmetricCipherKeyPair kp = TlsDHUtils.generateDHKeyPair(new SecureRandom(), tlsContext
		.getServerDHParameters().getPublicKey().getParameters());
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

	byte[] serializedPublicKey = BigIntegers.asUnsignedByteArray(protocolMessage.getY().getValue());
	protocolMessage.setSerializedPublicKey(serializedPublicKey);
	protocolMessage.setSerializedPublicKeyLength(serializedPublicKey.length);

	byte[] result = ArrayConverter.concatenate(ArrayConverter.intToBytes(protocolMessage
		.getSerializedPublicKeyLength().getValue(), HandshakeByteLength.DH_PARAM_LENGTH), protocolMessage
		.getSerializedPublicKey().getValue());

	byte[] premasterSecret = TlsDHUtils.calculateDHBasicAgreement(
		tlsContext.getServerDHParameters().getPublicKey(), newDhPrivate);
	protocolMessage.setPremasterSecret(premasterSecret);
	LOGGER.debug("Computed PreMaster Secret: {}",
		ArrayConverter.bytesToHexString(protocolMessage.getPremasterSecret().getValue()));

	byte[] random = tlsContext.getClientServerRandom();

	PRFAlgorithm prfAlgorithm = PRFAlgorithm.getPRFAlgorithm(tlsContext.getProtocolVersion(),
		tlsContext.getSelectedCipherSuite());
	byte[] masterSecret = PseudoRandomFunction.compute(tlsContext.getProtocolVersion(), protocolMessage
		.getPremasterSecret().getValue(), PseudoRandomFunction.MASTER_SECRET_LABEL, random,
		HandshakeByteLength.MASTER_SECRET, prfAlgorithm.getJavaName());
	LOGGER.debug("Computed Master Secret: {}", ArrayConverter.bytesToHexString(masterSecret));

	protocolMessage.setMasterSecret(masterSecret);
	tlsContext.setMasterSecret(protocolMessage.getMasterSecret().getValue());

	return result;

    }
}
