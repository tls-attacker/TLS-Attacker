/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ServerHelloDoneParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { new byte[0], ProtocolVersion.TLS12 },
            { new byte[0], ProtocolVersion.TLS10 }, { new byte[0], ProtocolVersion.TLS11 } });
    }

    private byte[] message;

    private ProtocolVersion version;
    private final Config config = Config.createConfig();

    public ServerHelloDoneParserTest(byte[] message, ProtocolVersion version) {
        this.message = message;
        this.version = version;
    }

    /**
     * Test of parse method, of class ServerHelloDoneParser.
     */
    @Test
    public void testParse() {
        ServerHelloDoneParser parser =
            new ServerHelloDoneParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        ServerHelloDoneMessage msg = new ServerHelloDoneMessage();
        parser.parse(msg);

    }

}
