package de.rub.nds.tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.CipherSuiteFilter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTraceType;
import java.util.Collections;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class FuzzerConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "fuzzer";

    @Parameter(names = "-server_command", description = "Command for starting the server")
    String serverCommand;

    @Parameter(names = "-server_command_file", description = "Command for starting the server, initialized from a given file.", converter = FileConverter.class)
    String serverCommandFile;

    @Parameter(names = "-modify_variable", description = "Probability of a random variable modification (0-100)", validateWith = PercentageValidator.class)
    Integer modifyVariablePercentage = 25;

    @Parameter(names = "-modified_variable_pattern", description = "Pattern for modifiable variables that are going to be modified randomly (e.g., defining length consideres only variables with length in name inside")
    String modifiedVariablePattern;

    @Parameter(names = "-duplicate_message", description = "Probability of a random message duplication", validateWith = PercentageValidator.class)
    Integer duplicateMessagePercentage = 15;

    @Parameter(names = "-not_sending_message", description = "Probability of a random message being not sent to the peer", validateWith = PercentageValidator.class)
    Integer notSendingMessagePercantage = 25;

    @Parameter(names = "-add_record", description = "Probability of adding a random record to a random protocol message (may cause the message is split into more records)", validateWith = PercentageValidator.class)
    Integer addRecordPercentage = 25;

    public FuzzerConfig() {
	cipherSuites.clear();
	cipherSuites.addAll(CipherSuite.getImplemented());
	// shuffle ciphersuites
	Collections.shuffle(cipherSuites);
	// filter ciphersuites so that only identical ciphersuites hold there
	CipherSuiteFilter.filterCipherSuites(cipherSuites);
	namedCurves.clear();
	namedCurves.add(NamedCurve.SECP192R1);
	namedCurves.add(NamedCurve.SECP256R1);
	namedCurves.add(NamedCurve.SECP521R1);
	workflowTraceType = WorkflowTraceType.HANDSHAKE;
    }

    public String getServerCommand() {
	return serverCommand;
    }

    public void setServerCommand(String serverCommand) {
	this.serverCommand = serverCommand;
    }

    public String getServerCommandFile() {
	return serverCommandFile;
    }

    public void setServerCommandFile(String serverCommandFile) {
	this.serverCommandFile = serverCommandFile;
    }

    public Integer getModifyVariablePercentage() {
	return modifyVariablePercentage;
    }

    public void setModifyVariablePercentage(Integer modifyVariablePercentage) {
	this.modifyVariablePercentage = modifyVariablePercentage;
    }

    public String getModifiedVariablePattern() {
	return modifiedVariablePattern;
    }

    public void setModifiedVariablePattern(String modifiedVariablePattern) {
	this.modifiedVariablePattern = modifiedVariablePattern;
    }

    public Integer getDuplicateMessagePercentage() {
	return duplicateMessagePercentage;
    }

    public void setDuplicateMessagePercentage(Integer duplicateMessagePercentage) {
	this.duplicateMessagePercentage = duplicateMessagePercentage;
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

}
