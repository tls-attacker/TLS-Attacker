/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import java.io.File;
import java.util.logging.Logger;

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
    public void createFolders()
    {
        File f = new File(configFolder);
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

    private static final Logger LOG = Logger.getLogger(FuzzerGeneralConfig.class.getName());
}
