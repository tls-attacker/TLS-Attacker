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
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.CipherSuite;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ServerCommandConfigTest {

    /**
     * Test config command line parsing
     */
    @Test
    public void testCommandLineParsing() {
	JCommander jc = new JCommander();

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);
	ClientCommandConfig client = new ClientCommandConfig();
	jc.addCommand(ClientCommandConfig.COMMAND, client);

	jc.parse("server", "-servername_fatal", "-keystore", "test.pem", "-password", "password");

	assertEquals("server", jc.getParsedCommand());
	assertTrue(server.isServerNameFatal());
	assertEquals("test.pem", server.getKeystore());
	assertEquals("password", server.getPassword());

	jc.parse("server", "-cipher", "TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA", "-version",
		"TLSv1.2");

	assertEquals("server", jc.getParsedCommand());
	assertEquals(2, server.getCipherSuites().size());
	assertEquals(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, server.getCipherSuites().get(0));
	assertEquals(ProtocolVersion.TLS12, server.getProtocolVersion());
    }

    /**
     * Test invalid config with invalid cipher suite
     */
    @Test(expected = ParameterException.class)
    public void testInvalidCommandLineParsing() {
	JCommander jc = new JCommander();

	ServerCommandConfig server = new ServerCommandConfig();
	jc.addCommand(ServerCommandConfig.COMMAND, server);

	jc.parse("server", "-cipher", "invalid,TLS_RSA_WITH_AES_256_CBC_SHA", "-version", "TLSv1.2");
    }

}
