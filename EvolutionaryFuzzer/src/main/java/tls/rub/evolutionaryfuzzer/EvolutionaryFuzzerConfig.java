/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.fuzzer.config.converters.PropertyFormatConverter;
import de.rub.nds.tlsattacker.fuzzer.config.converters.PropertyTypeConverter;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;

/**
 * A Config File which controls the EvolutionaryFuzzer. TODO Implement
 *
 * @author Robert Merget - robert.merget@rub.de
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EvolutionaryFuzzerConfig extends ClientCommandConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "simple_fuzzer";

    @Parameter(names = "-server_command_file", description = "Command for starting the server, initialized from a given file.", converter = FileConverter.class)
    String serverCommandFromFile;

    @Parameter(names = "-modify_variable", description = "Probability of a random variable modification (0-100), in steps 2 and 3", validateWith = PercentageValidator.class)
    Integer modifyVariablePercentage = 100;

    @Parameter(names = "-add_record", description = "Probability of adding a random record to a random protocol message (may cause the message is split into more records)", validateWith = PercentageValidator.class)
    Integer addRecordPercentage = 50;

    @Parameter(names = "-add_message", description = "Probability of adding a random message to a WorkflowTrace", validateWith = PercentageValidator.class)
    Integer addMessagePercentage = 10;

    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.")
    String outputFolder;

    /**
     * Constructor for EvolutionaryFuzzerConfig, defaults output Folder to "."
     * and serverCommandFromFile to server/server.config
     */
    public EvolutionaryFuzzerConfig() {
        outputFolder = ".";
        serverCommandFromFile = "server/server.config";
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
     * Message
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
            throw new IllegalArgumentException("ModifyVariablePercentage cannot be >100:" + verifyWorkflowCorrectness);
        }
    }

    /**
     * Gets an Integer representing the Chance that a Message is added to
     * WorkflowTrace, 0 representing 0% and 100 representing 100%
     *
     * @return Integer representing the Chance that a Message is added to
     * WorkflowTrace
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

    private static final Logger LOG = Logger.getLogger(EvolutionaryFuzzerConfig.class.getName());
}
