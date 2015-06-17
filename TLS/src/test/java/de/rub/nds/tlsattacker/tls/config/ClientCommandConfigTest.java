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
package de.rub.nds.tlsattacker.tls.config;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ClientCommandConfigTest {

    /**
     * Test config command line parsing
     */
    @Test
    public void testCommandLineParsing() {
	JCommander jc = new JCommander(new GeneralConfig());

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("client", "-connect", "localhost:443", "-keystore", "test.pem", "-password", "password",
		"-workflow_trace_type", "FULL");

	assertEquals("client", jc.getParsedCommand());
	assertEquals("localhost:443", client.getConnect());
	assertEquals("test.pem", client.getKeystore());
	assertEquals("password", client.getPassword());
    }

    /**
     * Test invalid config without connect parameter
     */
    @Test(expected = ParameterException.class)
    public void testInvalidCommandLineParsing() {
	JCommander jc = new JCommander();

	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("client", "-connect");
    }
}
