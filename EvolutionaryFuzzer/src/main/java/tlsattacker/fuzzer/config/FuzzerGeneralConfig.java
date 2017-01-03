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
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import java.io.File;

/**
 * A super class for configuration classes which allows for the configuration of
 * different commands.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerGeneralConfig extends ClientCommandConfig {

    /**
     * The agent that should be used
     */
    @Parameter(names = "-agent", description = "The Agent the Fuzzer uses to monitor the application (Default: AFL). Possible: AFL, PIN, BLIND")
    protected String agent = "AFL";

    /**
     * The agent that should be used
     */
    @Parameter(names = "-analyzer", description = "The Analyzer that should be used to analyze the Results (Default: rule). Possible: rule")
    protected String analyzer = "rule";

    /**
     * The folder with the configuration files
     */
    @Parameter(names = "-config_folder", description = "The Folder in which the config Files are", converter = FileConverter.class)
    protected String configFolder = "config/";

    /**
     * If a random port should be used on every server start
     */
    @Parameter(names = "-random_port", description = "Uses random ports for the Server")
    private boolean randomPort = false;

    /**
     * If the server should be used with the kill command specified in the
     * server config
     */
    @Parameter(names = "-use_kill", description = "Uses the kill command specified in the server configuration files.")
    private boolean useKill = false;

    /**
     * Timeout for server starts
     */
    @Parameter(names = "-boot_timeout", description = "The maximum time the fuzzer waits till the implementation boots up.")
    private Integer bootTimeout = 50000;

    /**
     * If set the PinAgent should inject into the child process TODO put in
     * agent config
     */
    @Parameter(names = "-inject_pin_child", description = "If the PIN Agent should instrument into the Childprocess")
    private final boolean injectPinChild = true;

    /**
     * The general folder in which results should be saved
     */
    @Parameter(names = "-output_folder", description = "Output folder for the fuzzing results.", converter = FileConverter.class)
    private String outputFolder = "./data/";

    /**
     * Temporary Folder which contains currently executed traces
     */
    private File tracesFolder;

    public FuzzerGeneralConfig() {
        outputFolder = "data/";
        this.tracesFolder = new File(outputFolder + "traces/");
        tracesFolder.mkdirs();
    }

    public String getAnalyzer() {
        return analyzer;
    }

    public boolean getInjectPinChild() {
        return injectPinChild;
    }

    public Integer getBootTimeout() {
        return bootTimeout;
    }

    public File getTracesFolder() {
        return tracesFolder;
    }

    public void setTracesFolder(File tracesFolder) {
        this.tracesFolder = tracesFolder;
    }

    public String getOutputFolder() {
        return outputFolder;
    }

    public String getOutputFaultyFolder() {
        return outputFolder + "faulty/";
    }

    public void setOutputFolder(String outputFolder) {
        this.outputFolder = outputFolder;
        this.tracesFolder = new File(outputFolder + "traces/");
    }

    public void setBootTimeout(Integer bootTimeout) {
        this.bootTimeout = bootTimeout;
    }

    public String getCertificateMutatorConfigFolder() {
        return configFolder + "mutator/certificate/";
    }

    public boolean isUseKill() {
        return useKill;
    }

    public void setUseKill(boolean useKill) {
        this.useKill = useKill;
    }

    public String getConfigFolder() {
        return configFolder;
    }

    public String getMutatorConfigFolder() {
        return configFolder + "mutator/";
    }

    public boolean isRandomPort() {
        return randomPort;
    }

    public void setRandomPort(boolean randomPort) {
        this.randomPort = randomPort;
    }

    public String getAnalyzerConfigFolder() {
        return configFolder + "analyzer/";
    }

    public void setConfigFolder(String configFolder) {
        this.configFolder = configFolder;
    }

    /**
     * Creates the Folders as specified in in the different Path fields
     */
    public void createFolders() {
        File f = new File(outputFolder);
        f.mkdirs();
        tracesFolder.mkdirs();// TODO check
        f = new File(configFolder);
        f.mkdirs();
        f = new File(getMutatorConfigFolder());
        f.mkdirs();
        f = new File(getAnalyzerConfigFolder());
        f.mkdirs();
        f = new File(getServerCommandFromFile());
        f.mkdirs();
    }

    public String getAgent() {
        return agent;
    }

    public void setAgent(String agent) {
        this.agent = agent;
    }

    public String getServerCommandFromFile() {
        return configFolder + "server/";
    }

}
