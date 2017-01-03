/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

/**
 * A configuration class for the "test-crashes" command
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Parameters(commandDescription = "Executes all TestVectors which crashed the Server while Fuzzing. This is useful to test if the Testvectors can reproduce the crash.")
public class TestCrashesConfig extends EvolutionaryFuzzerConfig {

    /**
     * The folder with the crashes that should be re executed
     */
    @Parameter(names = "-crash_folder", required = false, description = "The Folder which contains the crashes that should be tested")
    private String crashFolder = "data/crash/";

    /**
     * The number of times the testvectors should be executed
     */
    @Parameter(names = "-execute_times", description = "How often the crashes should be executed before they are discarded")
    private int executeNumber = 100;

    public String getCrashFolder() {
        return crashFolder;
    }

    public void setCrashFolder(String crashFolder) {
        this.crashFolder = crashFolder;
    }

    public int getExecuteNumber() {
        return executeNumber;
    }

    public void setExecuteNumber(int executeNumber) {
        this.executeNumber = executeNumber;
    }

}
