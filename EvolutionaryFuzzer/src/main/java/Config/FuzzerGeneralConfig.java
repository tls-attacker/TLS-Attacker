/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import java.io.File;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerGeneralConfig extends ClientCommandConfig {
    @Parameter(names = "-server_command_file", description = "Command for starting the server, initialized from a given File or Folder.", converter = FileConverter.class)
    protected String serverCommandFromFile = "server/";
    @Parameter(names = "-agent", description = "The Agent the Fuzzer uses to monitor the application (Default: AFL). Possible: AFL, PIN")
    protected String agent = "AFL";
    @Parameter(names = "-config_folder", description = "The Folder in which the config Files are", converter = FileConverter.class)
    protected String configFolder = "config/";
    protected String mutatorConfigFolder = configFolder + "mutator/";
    protected String certificateMutatorConfigFolder = mutatorConfigFolder + "certificate/";
    protected String analyzerConfigFolder = configFolder + "analyzer/";

    public String getCertificateMutatorConfigFolder() {
	return certificateMutatorConfigFolder;
    }

    public String getConfigFolder() {
	return configFolder;
    }

    public String getMutatorConfigFolder() {
	return mutatorConfigFolder;
    }

    public String getAnalyzerConfigFolder() {
	return analyzerConfigFolder;
    }

    public void setConfigFolder(String configFolder) {
	this.configFolder = configFolder;
	File f = new File(configFolder);
	f.mkdirs();
	f = new File(getMutatorConfigFolder());
	f.mkdirs();
	f = new File(getAnalyzerConfigFolder());
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
}
