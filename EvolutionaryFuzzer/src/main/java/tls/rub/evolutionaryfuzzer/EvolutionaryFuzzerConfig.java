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
 * A Config File which controls the EvolutionaryFuzzer.
 * TODO Implement
 * @author Robert Merget - robert.merget@rub.de
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EvolutionaryFuzzerConfig extends ClientCommandConfig
{

    /**
     *
     */
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

    @Parameter(names = "-add_record", description = "Probability of adding a random record to a random protocol message (may cause the message is split into more records)", validateWith = PercentageValidator.class)
    Integer addRecordPercentage = 50;

    @Parameter(names = "-restart_server", description = "Indicates whether the server is restarted in each fuzzing iteration.")
    boolean restartServerInEachInteration = false;

    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.")
    String outputFolder;

    @Parameter(names = "-workflow_folder", description = "Folder with tested workflows.")
    String workflowFolder;

    /**
     *
     */
    public EvolutionaryFuzzerConfig()
    {
        modifiableVariableTypes = new LinkedList<>();
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.COUNT);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.LENGTH);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.PADDING);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.COOKIE);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.KEY_MATERIAL);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.SIGNATURE);
        modifiableVariableTypes.add(ModifiableVariableProperty.Type.TLS_CONSTANT);

        modifiableVariableFormats = new LinkedList<>();
        modifiableVariableFormats.add(ModifiableVariableProperty.Format.NONE);
        modifiableVariableFormats.add(ModifiableVariableProperty.Format.ASN1);
        modifiableVariableFormats.add(ModifiableVariableProperty.Format.PKCS1);

        outputFolder = "/tmp/";

	//tlsTimeout = 80;
    }

    /**
     *
     * @return
     */
    public String getServerCommand()
    {
        return serverCommand;
    }

    /**
     *
     * @param serverCommand
     */
    public void setServerCommand(String serverCommand)
    {
        this.serverCommand = serverCommand;
    }

    /**
     *
     * @return
     */
    public String getServerCommandFromFile()
    {
        return serverCommandFromFile;
    }

    /**
     *
     * @param serverCommandFromFile
     */
    public void setServerCommandFromFile(String serverCommandFromFile)
    {
        this.serverCommandFromFile = serverCommandFromFile;
    }

    /**
     *
     * @return
     */
    public Integer getModifyVariablePercentage()
    {
        return modifyVariablePercentage;
    }

    /**
     *
     * @param modifyVariablePercentage
     */
    public void setModifyVariablePercentage(Integer modifyVariablePercentage)
    {
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
    /**
     *
     * @return
     */
    public List<ModifiableVariableProperty.Type> getModifiableVariableTypes()
    {
        return Collections.unmodifiableList(modifiableVariableTypes);
    }

    /**
     *
     * @param modifiableVariableTypes
     */
    public void setModifiableVariableTypes(List<ModifiableVariableProperty.Type> modifiableVariableTypes)
    {
        this.modifiableVariableTypes = modifiableVariableTypes;
    }

    /**
     *
     * @return
     */
    public List<ModifiableVariableProperty.Format> getModifiableVariableFormats()
    {
        return Collections.unmodifiableList(modifiableVariableFormats);
    }

    /**
     *
     * @param modifiableVariableFormats
     */
    public void setModifiableVariableFormats(List<ModifiableVariableProperty.Format> modifiableVariableFormats)
    {
        this.modifiableVariableFormats = modifiableVariableFormats;
    }

    /**
     *
     * @return
     */
    public Integer getAddRecordPercentage()
    {
        return addRecordPercentage;
    }

    /**
     *
     * @param addRecordPercentage
     */
    public void setAddRecordPercentage(Integer addRecordPercentage)
    {
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
    /**
     *
     * @return
     */
    public String getModifiedVariableWhitelist()
    {
        return modifiedVariableWhitelist;
    }

    /**
     *
     * @param modifiedVariableWhitelist
     */
    public void setModifiedVariableWhitelist(String modifiedVariableWhitelist)
    {
        this.modifiedVariableWhitelist = modifiedVariableWhitelist;
    }

    /**
     *
     * @return
     */
    public String getModifiedVariableBlacklist()
    {
        return modifiedVariableBlacklist;
    }

    /**
     *
     * @param modifiedVariableBlacklist
     */
    public void setModifiedVariableBlacklist(String modifiedVariableBlacklist)
    {
        this.modifiedVariableBlacklist = modifiedVariableBlacklist;
    }

    /**
     *
     * @return
     */
    public boolean isRestartServerInEachInteration()
    {
        return restartServerInEachInteration;
    }

    /**
     *
     * @param restartServerInEachInteration
     */
    public void setRestartServerInEachInteration(boolean restartServerInEachInteration)
    {
        this.restartServerInEachInteration = restartServerInEachInteration;
    }

    /**
     *
     * @return
     */
    public String getOutputFolder()
    {
        return outputFolder;
    }

    /**
     *
     * @param outputFolder
     */
    public void setOutputFolder(String outputFolder)
    {
        this.outputFolder = outputFolder;
    }

    /**
     *
     * @return
     */
    public String getWorkflowFolder()
    {
        return workflowFolder;
    }

    /**
     *
     * @param workflowFolder
     */
    public void setWorkflowFolder(String workflowFolder)
    {
        this.workflowFolder = workflowFolder;
    }

    /**
     *
     * @return
     */
    public boolean containsServerCommand()
    {
        return serverCommand != null || serverCommandFromFile != null;
    }

    /**
     *
     * @return
     */
    public String getResultingServerCommand()
    {
        if (serverCommand != null)
        {
            return serverCommand;
        }
        else
        {
            return serverCommandFromFile;
        }
    }
    private static final Logger LOG = Logger.getLogger(EvolutionaryFuzzerConfig.class.getName());
}
