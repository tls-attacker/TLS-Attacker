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
package de.rub.nds.tlsattacker.fuzzer.config;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
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
