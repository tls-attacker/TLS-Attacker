package Config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.validators.PositiveInteger;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;
import java.util.logging.Logger;

/**
 * A Config File which controls the EvolutionaryFuzzer.
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EvolutionaryFuzzerConfig extends ClientCommandConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "fuzzer";
    private static final Logger LOG = Logger.getLogger(EvolutionaryFuzzerConfig.class.getName());

    @Parameter(names = "-server_command_file", description = "Command for starting the server, initialized from a given File or Folder.", converter = FileConverter.class)
    private String serverCommandFromFile = "server/";

    @Parameter(names = "-modify_variable", description = "Probability of a random variable modification (0-100), in steps 2 and 3", validateWith = PercentageValidator.class)
    private Integer modifyVariablePercentage = 90;

    @Parameter(names = "-add_record", description = "Probability of adding a random record to a random protocol message (may cause the message is split into more records)", validateWith = PercentageValidator.class)
    private Integer addRecordPercentage = 50;

    @Parameter(names = "-add_message", description = "Probability of adding a random message to a WorkflowTrace", validateWith = PercentageValidator.class)
    private Integer addMessagePercentage = 50;
    @Parameter(names = "-remove_message", description = "Probability of removing a random message from a WorkflowTrace", validateWith = PercentageValidator.class)
    private Integer removeMessagePercentage = 1;
    @Parameter(names = "-duplicate_message", description = "Probability of duplicating a random message from a WorkflowTrace", validateWith = PercentageValidator.class)
    private Integer duplicateMessagePercentage = 1;

    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.", converter = FileConverter.class)
    private String outputFolder = "./";
    @Parameter(names = "-threads", description = "Number of Threads running Simultaniously, (Default:Number of Server in Config)", validateWith = PositiveInteger.class)
    private Integer threads = -1;
    @Parameter(names = "-agent", description = "The Agent the Fuzzer uses to monitor the application (Default: AFL). Possible: AFL, PIN")
    private String agent = "AFL";

    // Are we currently in serialization mode?
    private boolean serialize = false;

    /**
     * Constructor for EvolutionaryFuzzerConfig, defaults output Folder to "."
     * and serverCommandFromFile to server/server.config
     */
    public EvolutionaryFuzzerConfig() {
	outputFolder = "./";
	serverCommandFromFile = "server/";
	this.timeout = 60000;
    }

    public boolean isSerialize() {
	return serialize;
    }

    public void setSerialize(boolean serialize) {
	this.serialize = serialize;
    }

    public String getAgent() {
	return agent;
    }

    public void setAgent(String agent) {
	this.agent = agent;
    }

    public Integer getDuplicateMessagePercentage() {
	return duplicateMessagePercentage;
    }

    public void setDuplicateMessagePercentage(Integer duplicateMessagePercentage) {
	this.duplicateMessagePercentage = duplicateMessagePercentage;
    }

    public Integer getThreads() {
	return threads;
    }

    public void setThreads(Integer threads) {
	this.threads = threads;
    }

    public Integer getRemoveMessagePercentage() {
	return removeMessagePercentage;
    }

    public void setRemoveMessagePercentage(Integer removeMessagePercentage) {
	this.removeMessagePercentage = removeMessagePercentage;
	if (removeMessagePercentage > 100) {
	    throw new IllegalArgumentException("RemoveMessagePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Returns the path to the ServerConfig File
     * 
     * @return Path to the ServerConfig File
     */
    public String getServerCommandFromFile() {
	return serverCommandFromFile;
    }

    /**
     * Sets the path to the ServerConfig File
     * 
     * @param serverCommandFromFile
     */
    public void setServerCommandFromFile(String serverCommandFromFile) {
	this.serverCommandFromFile = serverCommandFromFile;
    }

    /**
     * Returns an Integer representing the chance that a Variable Modification
     * occurs in a Workflow Trace, 0 representing 0% and 100 representing 100%
     * 
     * @return
     */
    public Integer getModifyVariablePercentage() {
	return modifyVariablePercentage;
    }

    /**
     * Sets an Integer representing the chance that a Variable Modification
     * occurs in a Workflow Trace, 0 representing 0% and 100 representing 100%
     * 
     * @param modifyVariablePercentage
     */
    public void setModifyVariablePercentage(Integer modifyVariablePercentage) {
	this.modifyVariablePercentage = modifyVariablePercentage;
	if (modifyVariablePercentage > 100) {
	    throw new IllegalArgumentException("ModifyVariablePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Gets an Integer representing the Chance that a record is added to a
     * Message, 0 representing 0% and 100 representing 100%
     * 
     * @return Integer representing the Chance that a record is added to a
     *         Message
     */
    public Integer getAddRecordPercentage() {
	return addRecordPercentage;

    }

    /**
     * Sets an Integer representing the Chance that a record is added to a
     * Message, 0 representing 0% and 100 representing 100%
     * 
     * @param addRecordPercentage
     */
    public void setAddRecordPercentage(Integer addRecordPercentage) {
	this.addRecordPercentage = addRecordPercentage;
	if (addRecordPercentage > 100) {
	    throw new IllegalArgumentException("AddRecordPercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Gets an Integer representing the Chance that a Message is added to
     * WorkflowTrace, 0 representing 0% and 100 representing 100%
     * 
     * @return Integer representing the Chance that a Message is added to
     *         WorkflowTrace
     */
    public Integer getAddMessagePercentage() {
	return addMessagePercentage;
    }

    /**
     * Sets an Integer representing the Chance that a Message is added to
     * WorkflowTrace, 0 representing 0% and 100 representing 100%
     * 
     * @param addMessagePercentage
     */
    public void setAddMessagePercentage(Integer addMessagePercentage) {
	this.addMessagePercentage = addMessagePercentage;
	if (addMessagePercentage > 100) {
	    throw new IllegalArgumentException("AddMessagePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Returns the Path to the Folder in which the Fuzzer will save its output
     * to. The Server will genereate several Folder in the Output Folder.
     * 
     * @return Path to the Folder in which the Fuzzer will save its output to
     */
    public String getOutputFolder() {
	return outputFolder;
    }

    /**
     * Sets the Path to the Folder in which the Fuzzer will save its output to.
     * The Server will genereate several Folder in the Output Folder.
     * 
     * @param outputFolder
     */
    public void setOutputFolder(String outputFolder) {
	this.outputFolder = outputFolder;
    }

}
