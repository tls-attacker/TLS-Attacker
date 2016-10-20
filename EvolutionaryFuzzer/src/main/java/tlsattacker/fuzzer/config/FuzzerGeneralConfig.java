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

/**
 * A super class for configuration classes which allows for the configuration of different commands.
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerGeneralConfig extends ClientCommandConfig {

    @Parameter(names = "-agent", description = "The Agent the Fuzzer uses to monitor the application (Default: AFL). Possible: AFL, PIN, BLIND")
    protected String agent = "AFL";
    @Parameter(names = "-config_folder", description = "The Folder in which the config Files are", converter = FileConverter.class)
    protected String configFolder = "config/";
    @Parameter(names = "-random_port", description = "Uses random ports for the Server")
    private boolean randomPort = false;
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

    /**
     * Returns the path to the ServerConfig File
     * 
     * @return Path to the ServerConfig File
     */
    public String getServerCommandFromFile() {
	return configFolder + "server/";
    }
}
