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
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class DtlsPoodleCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "dtls_poodle";

    @Parameter(names = "-messagespertrain", description = "Number of messages per train")
    public int messagesPerTrain = 10;

    @Parameter(names = "-trainmessagesize", description = "Message size of each trains messages")
    public int trainMessageSize = 1450;

    @Parameter(names = "-rounds", description = "Number of attack rounds")
    public int nrOfRounds = 20;

    @Parameter(names = "-resultfile", description = "Save the response times in the specified file")
    public String resultFilePath = null;

    public DtlsPoodleCommandConfig() {
	// Just to be sure
	transportHandlerType = TransportHandlerType.UDP;
	protocolVersion = ProtocolVersion.DTLS12;
	workflowTraceType = WorkflowTraceType.HANDSHAKE;

	// Until all dtls workflow factories are adapted, this is to make sure
	// the right workflow factory is used
	List<CipherSuite> cs = new ArrayList<>();
	cs.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites = cs;
    }

    public int getMessagesPerTrain() {
	return messagesPerTrain;
    }

    public int getTrainMessageSize() {
	return trainMessageSize;
    }

    public int getNrOfRounds() {
	return nrOfRounds;
    }

    public String getResultFilePath() {
	return resultFilePath;
    }

    public void setMessagesPerTrain(int messagesPerTrain) {
	this.messagesPerTrain = messagesPerTrain;
    }

    public void setTrainMessageSize(int trainMessageSize) {
	this.trainMessageSize = trainMessageSize;
    }

    public void setNrOfRounds(int nrOfRounds) {
	this.nrOfRounds = nrOfRounds;
    }

    public void setResultFilePath(String resultFilePath) {
	this.resultFilePath = resultFilePath;
    }
}