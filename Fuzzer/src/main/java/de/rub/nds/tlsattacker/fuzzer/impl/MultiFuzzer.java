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
package de.rub.nds.tlsattacker.fuzzer.impl;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.config.SimpleFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.config.StartupCommand;
import de.rub.nds.tlsattacker.fuzzer.config.StartupCommandsHolder;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.FileNotFoundException;
import java.io.FileReader;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class MultiFuzzer extends Fuzzer {

    public static Logger LOGGER = LogManager.getLogger(MultiFuzzer.class);

    private final MultiFuzzerConfig fuzzerConfig;

    public MultiFuzzer(MultiFuzzerConfig config, GeneralConfig generalConfig) {
	super(generalConfig);
	this.fuzzerConfig = config;
    }

    @Override
    public void startFuzzer() {
	String file = fuzzerConfig.getStartupCommandFile();
	try {
	    StartupCommandsHolder holder = unmarshalStartupCommands(file);
	    for (StartupCommand command : holder.getStartupCommands()) {
		String fullServerCommand = holder.getServerCommand() + " " + command.getServerCommandParameters();
		LOGGER.info("Starting new fuzzer with the follwing parameters");
		LOGGER.info("  Name: {}", command.getShortName());
		LOGGER.info("  Server command: {}", fullServerCommand);
		LOGGER.info("  Fuzzer config: {}", command.getFuzzerCommand());

		SimpleFuzzerConfig simpleConfig = parseSimpleFuzzerConfig(command);
		simpleConfig.setServerCommand(fullServerCommand);

		SimpleFuzzer fuzzer = new SimpleFuzzer(simpleConfig, generalConfig);
		fuzzer.setFuzzingName(command.getShortName());

		new SimpleFuzzerStarter(fuzzer).start();
	    }
	} catch (FileNotFoundException | JAXBException ex) {
	    throw new ConfigurationException("Unmarshaling failed", ex);
	}
    }

    /**
     * Parses the simple fuzzer configuration, typically used from the main
     * class.
     * 
     * @param command
     * @return
     */
    private SimpleFuzzerConfig parseSimpleFuzzerConfig(StartupCommand command) {
	JCommander jc = new JCommander();
	SimpleFuzzerConfig simpleConfig = new SimpleFuzzerConfig();
	jc.addCommand(SimpleFuzzerConfig.ATTACK_COMMAND, simpleConfig);
	jc.parse(command.getFuzzerCommand().split(" "));
	return simpleConfig;
    }

    /**
     * Unmarshals the startup commands (for server and fuzzer) from an XML file
     * 
     * @param file
     * @return
     * @throws JAXBException
     * @throws FileNotFoundException
     */
    private StartupCommandsHolder unmarshalStartupCommands(String file) throws JAXBException, FileNotFoundException {
	JAXBContext context = JAXBContext.newInstance(StartupCommandsHolder.class);
	Unmarshaller um = context.createUnmarshaller();
	return (StartupCommandsHolder) um.unmarshal(new FileReader(file));
    }

    class SimpleFuzzerStarter extends Thread {
	private final SimpleFuzzer fuzzer;

	public SimpleFuzzerStarter(SimpleFuzzer fuzzer) {
	    this.fuzzer = fuzzer;
	}

	@Override
	public void run() {
	    fuzzer.startFuzzer();
	}
    }
}
