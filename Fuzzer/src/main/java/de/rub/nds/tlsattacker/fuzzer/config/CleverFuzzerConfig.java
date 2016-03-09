/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
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
package de.rub.nds.tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.fuzzer.config.converters.PropertyFormatConverter;
import de.rub.nds.tlsattacker.fuzzer.config.converters.PropertyTypeConverter;
import de.rub.nds.tlsattacker.fuzzer.impl.FuzzingType;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CleverFuzzerConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "simple_fuzzer";

    @Parameter(names = "-server_command", description = "Command for starting the server")
    String serverCommand;

    @Parameter(names = "-server_command_file", description = "Command for starting the server, initialized from a given file.", converter = FileConverter.class)
    String serverCommandFromFile;

    @Parameter(names = "-modify_variable", description = "Probability of a random variable modification (0-100), in steps 2 and 3", validateWith = PercentageValidator.class)
    Integer modifyVariablePercentage = 50;

    @Parameter(names = "-modified_variable_whitelist", description = "Pattern for modifiable variables that are going to be modified randomly (e.g., defining *length consideres only variables ending with length")
    String modifiedVariableWhitelist;

    @Parameter(names = "-modified_variable_blacklist", description = "Pattern for modifiable variables that are NOT going to be modified randomly (e.g., defining *length consideres variables ending with length are out of modification scope.")
    String modifiedVariableBlacklist;

    @Parameter(names = "-modified_variable_types", description = "Type of modifiable variables that are going to be modified randomly (e.g., defining LENGTH consideres only length variables)", converter = PropertyTypeConverter.class)
    List<ModifiableVariableProperty.Type> modifiableVariableTypes;

    @Parameter(names = "-modified_variable_formats", description = "Format of modifiable variables that are going to be modified randomly (e.g., defining ASN1 consideres only variables with ASN.1 formats)", converter = PropertyFormatConverter.class)
    List<ModifiableVariableProperty.Format> modifiableVariableFormats;

    @Parameter(names = "-generate_message", description = "Probability of a random message generation in step 3", validateWith = PercentageValidator.class)
    Integer generateMessagePercentage = 50;

    @Parameter(names = "-not_sending_message", description = "Probability of a random message being not sent to the peer in step 3", validateWith = PercentageValidator.class)
    Integer notSendingMessagePercantage = 50;

    @Parameter(names = "-add_record", description = "Probability of adding a random record to a random protocol message (may cause the message is split into more records)", validateWith = PercentageValidator.class)
    Integer addRecordPercentage = 50;

    // @Parameter(names = "-interrupt", description =
    // "Interrupts scan after first finding resulting in an invalid workflow.")
    // boolean interruptAfterFirstFinding;
    @Parameter(names = "-fuzzing_type", description = "Fuzzing can be either done completely randomly, or systematically iterating over modifiable variable.")
    FuzzingType fuzzingType = FuzzingType.CLEVER;

    @Parameter(names = "-variable_modification_iter", description = "Number of modifications made to each field while executing a systematic fuzzing in step 1.")
    Integer variableModificationIter = 1000;

    @Parameter(names = "-random_modification_iter", description = "Number of random modifications made to a handshake while executing a systematic fuzzing in step 2.")
    Integer randomModificationIter = 10000;

    @Parameter(names = "-handshake_modification_iter", description = "Number of random modifications to the handshake made while fuzzing in step 3.")
    Integer handshakeModificationIter = 10000;

    @Parameter(names = "-restart_server", description = "Indicates whether the server is restarted in each fuzzing iteration.")
    boolean restartServerInEachInteration = false;

    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.")
    String outputFolder;

    @Parameter(names = "-workflow_folder", description = "Folder with tested workflows.")
    String workflowFolder;

    public CleverFuzzerConfig() {
	modifiableVariableTypes = new LinkedList<>();
	modifiableVariableTypes.add(ModifiableVariableProperty.Type.COUNT);
	modifiableVariableTypes.add(ModifiableVariableProperty.Type.LENGTH);
	modifiableVariableTypes.add(ModifiableVariableProperty.Type.PADDING);

	modifiableVariableFormats = new LinkedList<>();
	modifiableVariableFormats.add(ModifiableVariableProperty.Format.NONE);
	modifiableVariableFormats.add(ModifiableVariableProperty.Format.ASN1);
	modifiableVariableFormats.add(ModifiableVariableProperty.Format.PKCS1);

	outputFolder = "/tmp/";
    }

    public String getServerCommand() {
	return serverCommand;
    }

    public void setServerCommand(String serverCommand) {
	this.serverCommand = serverCommand;
    }

    public String getServerCommandFromFile() {
	return serverCommandFromFile;
    }

    public void setServerCommandFromFile(String serverCommandFromFile) {
	this.serverCommandFromFile = serverCommandFromFile;
    }

    public Integer getModifyVariablePercentage() {
	return modifyVariablePercentage;
    }

    public void setModifyVariablePercentage(Integer modifyVariablePercentage) {
	this.modifyVariablePercentage = modifyVariablePercentage;
    }

    // public String getModifiedVariablePattern() {
    // return modifiedVariableWhitelist;
    // }
    //
    // public void setModifiedVariablePattern(String modifiedVariableWhitelist)
    // {
    // this.modifiedVariableWhitelist = modifiedVariableWhitelist;
    // }
    public List<ModifiableVariableProperty.Type> getModifiableVariableTypes() {
	return modifiableVariableTypes;
    }

    public void setModifiableVariableTypes(List<ModifiableVariableProperty.Type> modifiableVariableTypes) {
	this.modifiableVariableTypes = modifiableVariableTypes;
    }

    public List<ModifiableVariableProperty.Format> getModifiableVariableFormats() {
	return modifiableVariableFormats;
    }

    public void setModifiableVariableFormats(List<ModifiableVariableProperty.Format> modifiableVariableFormats) {
	this.modifiableVariableFormats = modifiableVariableFormats;
    }

    public Integer getGenerateMessagePercentage() {
	return generateMessagePercentage;
    }

    public void setGenerateMessagePercentage(Integer generateMessagePercentage) {
	this.generateMessagePercentage = generateMessagePercentage;
    }

    public Integer getNotSendingMessagePercantage() {
	return notSendingMessagePercantage;
    }

    public void setNotSendingMessagePercantage(Integer notSendingMessagePercantage) {
	this.notSendingMessagePercantage = notSendingMessagePercantage;
    }

    public Integer getAddRecordPercentage() {
	return addRecordPercentage;
    }

    public void setAddRecordPercentage(Integer addRecordPercentage) {
	this.addRecordPercentage = addRecordPercentage;
    }

    // public boolean isInterruptAfterFirstFinding() {
    // return interruptAfterFirstFinding;
    // }
    //
    // public void setInterruptAfterFirstFinding(boolean
    // interruptAfterFirstFinding) {
    // this.interruptAfterFirstFinding = interruptAfterFirstFinding;
    // }
    public String getModifiedVariableWhitelist() {
	return modifiedVariableWhitelist;
    }

    public void setModifiedVariableWhitelist(String modifiedVariableWhitelist) {
	this.modifiedVariableWhitelist = modifiedVariableWhitelist;
    }

    public String getModifiedVariableBlacklist() {
	return modifiedVariableBlacklist;
    }

    public void setModifiedVariableBlacklist(String modifiedVariableBlacklist) {
	this.modifiedVariableBlacklist = modifiedVariableBlacklist;
    }

    public FuzzingType getFuzzingType() {
	return fuzzingType;
    }

    public void setFuzzingType(FuzzingType fuzzingType) {
	this.fuzzingType = fuzzingType;
    }

    public Integer getVariableModificationIter() {
	return variableModificationIter;
    }

    public void setVariableModificationIter(Integer variableModificationIter) {
	this.variableModificationIter = variableModificationIter;
    }

    public boolean isRestartServerInEachInteration() {
	return restartServerInEachInteration;
    }

    public void setRestartServerInEachInteration(boolean restartServerInEachInteration) {
	this.restartServerInEachInteration = restartServerInEachInteration;
    }

    public Integer getRandomModificationIter() {
	return randomModificationIter;
    }

    public void setRandomModificationIter(Integer randomModificationIter) {
	this.randomModificationIter = randomModificationIter;
    }

    public Integer getHandshakeModificationIter() {
	return handshakeModificationIter;
    }

    public void setHandshakeModificationIter(Integer handshakeModificationIter) {
	this.handshakeModificationIter = handshakeModificationIter;
    }

    public String getOutputFolder() {
	return outputFolder;
    }

    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }

    public String getWorkflowFolder() {
	return workflowFolder;
    }

    public void setWorkflowFolder(String workflowFolder) {
	this.workflowFolder = workflowFolder;
    }

    public boolean containsServerCommand() {
	return serverCommand != null || serverCommandFromFile != null;
    }

    public String getResultingServerCommand() {
	if (serverCommand != null) {
	    return serverCommand;
	} else {
	    return serverCommandFromFile;
	}
    }
}
