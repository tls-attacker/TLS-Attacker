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
public class DtlsPaddingOracleAttackSweepTestCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "dtls_potestsweep";

    @Parameter(names = "-messagespertrain", description = "Number of messages per train")
    protected int messagesPerTrain = 10;

    @Parameter(names = "-startmessagesize", description = "Start with messages of this size (in bytes)")
    protected int startMessageSize = 64;

    @Parameter(names = "-endmessagesize", description = "End when message size is about to exceed this threshold (in bytes)")
    protected int endMessageSize = 1408;

    @Parameter(names = "-msincrement", description = "Value by which the message size will be increased in each iteration (in byt"
	    + "es)")
    protected int messageSizeIncrementPerIteration = 64;

    @Parameter(names = "-roundsperiteration", description = "Number of rounds per iteration/message size. Note, that this is NOT "
	    + "the full number of rounds of this test. The full number of rounds for the whole test will be 'ceil([(endmessagesiz"
	    + "e - startmessagesize) / msincrement] * roundsperiteration)', e.g. for the default values this will be ((1450 - 100"
	    + ") / 10) * 20 = 2700.")
    protected int nrOfRoundsPerIteration = 20;

    @Parameter(names = "-resultfile", description = "Save the response times in the specified file")
    protected String resultFilePath = null;

    public DtlsPaddingOracleAttackSweepTestCommandConfig() {
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

    public int getStartMessageSize() {
	return startMessageSize;
    }

    public int getEndMessageSize() {
	return endMessageSize;
    }

    public int getMessageSizeIncrement() {
	return messageSizeIncrementPerIteration;
    }

    public int getNrOfRoundsPerIteration() {
	return nrOfRoundsPerIteration;
    }

    public String getResultFilePath() {
	return resultFilePath;
    }

    public void setMessagesPerTrain(int messagesPerTrain) {
	this.messagesPerTrain = messagesPerTrain;
    }

    public void setStartMessageSize(int trainMessageSize) {
	this.startMessageSize = trainMessageSize;
    }

    public void setEndMessageSize(int endMessageSize) {
	this.endMessageSize = endMessageSize;
    }

    public void setMessageSizeIncrementPerIteration(int messageSizeIncrementPerIteration) {
	this.messageSizeIncrementPerIteration = messageSizeIncrementPerIteration;
    }

    public void setNrOfRoundsPerIteration(int nrOfRounds) {
	this.nrOfRoundsPerIteration = nrOfRounds;
    }

    public void setResultFilePath(String resultFilePath) {
	this.resultFilePath = resultFilePath;
    }
}