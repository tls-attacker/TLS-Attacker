/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.config;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Before;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class StartupCommandsHolderTest {

    private static final Logger LOGGER = LogManager.getLogger(StartupCommandsHolderTest.class);

    private String startupServerCommand, startupFuzzerCommand, startupShortName;

    private StringWriter writer;

    private JAXBContext context;

    private Marshaller m;

    private Unmarshaller um;

    private StartupCommandsHolder holder;

    @Before
    public void setUp() throws JAXBException {
	startupFuzzerCommand = "fuzzing command";
	startupServerCommand = "server command";
	startupShortName = "short name";
	holder = new StartupCommandsHolder();

	writer = new StringWriter();
	context = JAXBContext.newInstance(StartupCommandsHolder.class);
	m = context.createMarshaller();
	m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
	um = context.createUnmarshaller();
    }

    @Test
    public void serializationTest() throws JAXBException {
	StartupCommand command = new StartupCommand();
	command.setFuzzerCommand(startupFuzzerCommand);
	command.setServerCommandParameters(startupServerCommand);
	command.setShortName(startupShortName);
	List<StartupCommand> commands = new LinkedList<>();
	commands.add(command);
	holder.setStartupCommands(commands);

	m.marshal(holder, writer);

	String xmlString = writer.toString();
	LOGGER.debug(xmlString);

	um = context.createUnmarshaller();
	StartupCommandsHolder holder2 = (StartupCommandsHolder) um.unmarshal(new StringReader(xmlString));

	StartupCommand deserialized = holder2.getStartupCommands().get(0);
	assertEquals(startupFuzzerCommand, deserialized.getFuzzerCommand());
	assertEquals(startupServerCommand, deserialized.getServerCommandParameters());
	assertEquals(startupShortName, deserialized.getShortName());
    }

}
