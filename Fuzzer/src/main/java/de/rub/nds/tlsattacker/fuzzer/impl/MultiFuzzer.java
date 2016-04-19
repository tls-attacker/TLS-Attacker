/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.fuzzer.impl;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.fuzzer.config.SimpleFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.config.MultiFuzzerConfig;
import de.rub.nds.tlsattacker.fuzzer.config.StartupCommand;
import de.rub.nds.tlsattacker.fuzzer.config.StartupCommandsHolder;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
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
	    int port = holder.getServerPort();
	    String types = holder.getModifiedVariableTypes();
	    for (StartupCommand command : holder.getStartupCommands()) {
		String fullServerCommand = null;
		if (holder.getServerCommand() != null && !holder.getServerCommand().isEmpty()) {
		    fullServerCommand = holder.getServerCommand() + " " + command.getServerCommandParameters();
		    fullServerCommand = fullServerCommand.replace("$PORT", Integer.toString(port));
		}
		String fuzzerCommand = command.getFuzzerCommand().replace("$PORT", Integer.toString(port));
		if (types != null && !types.isEmpty()) {
		    fuzzerCommand = fuzzerCommand + " -modified_variable_types " + types;
		}
		if (holder.getOutputFolder() != null && !holder.getOutputFolder().isEmpty()) {
		    fuzzerCommand = fuzzerCommand + " -output_folder " + holder.getOutputFolder();
		}
		if (holder.getWorkflowFolder() != null && !holder.getWorkflowFolder().isEmpty()) {
		    fuzzerCommand = fuzzerCommand + " -workflow_folder " + holder.getWorkflowFolder();
		}
		LOGGER.info("Starting new fuzzer with the following parameters");
		LOGGER.info("  Name: {}", command.getShortName());
		LOGGER.info("  Server command: {}", fullServerCommand);
		LOGGER.info("  Fuzzer config: {}", fuzzerCommand);

		command.setFuzzerCommand(fuzzerCommand);
		SimpleFuzzerConfig simpleConfig = parseSimpleFuzzerConfig(command);
		simpleConfig.setServerCommand(fullServerCommand);

		SimpleFuzzer fuzzer = new SimpleFuzzer(simpleConfig, generalConfig);
		fuzzer.setFuzzingName(command.getShortName());

		new FuzzerStarter(fuzzer, command.getShortName()).start();
		port++;
	    }
	} catch (FileNotFoundException | JAXBException | XMLStreamException ex) {
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
    private StartupCommandsHolder unmarshalStartupCommands(String file) throws JAXBException, FileNotFoundException,
	    XMLStreamException {
	JAXBContext context = JAXBContext.newInstance(StartupCommandsHolder.class);
	Unmarshaller um = context.createUnmarshaller();

	XMLInputFactory xif = XMLInputFactory.newFactory();
	xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
	xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
	XMLStreamReader xsr = xif.createXMLStreamReader(new FileInputStream(file));

	return (StartupCommandsHolder) um.unmarshal(xsr);
    }

    class FuzzerStarter extends Thread {

	private final SimpleFuzzer fuzzer;

	public FuzzerStarter(SimpleFuzzer fuzzer, String name) {
	    super(name);
	    this.fuzzer = fuzzer;
	}

	@Override
	public void run() {
	    fuzzer.startFuzzer();
	}
    }
}
