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
package de.rub.nds.tlsattacker.attacks.impl;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherTestCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.alert.messages.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes
 * the server responses. In case there are differences in the server responses,
 * it is very likely that it is possible to execute Bleichenbacher attacks.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class BleichenbacherAttackTest extends Attacker<BleichenbacherTestCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(BleichenbacherAttackTest.class);

    public BleichenbacherAttackTest(BleichenbacherTestCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(config);
	LOGGER.info("Fetched the following server public key: " + publicKey);

	List<ProtocolMessage> protocolMessages = new LinkedList<>();
	byte[][] vectors = PKCS1VectorGenerator.generatePkcs1Vectors(publicKey);
	for (int i = 0; i < vectors.length; i++) {
	    ProtocolMessage pm = executeTlsFlow(configHandler, vectors[i]);
	    protocolMessages.add(pm);
	}

	LOGGER.info("The following list of protocol messages was found (the last protocol message in the client-server communication):");
	for (ProtocolMessage pm : protocolMessages) {
	    LOGGER.info("Sent by: {}, Type: {}", pm.getMessageIssuer(), pm.getProtocolMessageType());
	    if (pm.getProtocolMessageType() == ProtocolMessageType.ALERT) {
		AlertMessage alert = (AlertMessage) pm;
		LOGGER.info("  Alert {}: {}", alert.getLevel(), alert.getDescription());
	    }
	}

    }

    private ProtocolMessage executeTlsFlow(ConfigHandler configHandler, byte[] encryptedPMS) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	ModifiableByteArray epms = new ModifiableByteArray();
	epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
	cke.setEncryptedPremasterSecret(epms);

	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();
	return trace.getProtocolMessages().get(trace.getProtocolMessages().size() - 1);
    }

}
