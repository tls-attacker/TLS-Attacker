/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerNamePairParser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SNI.ServerNamePair;
import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
@RunWith(Parameterized.class)
public class ServerNamePairParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { // TODO collect a real
                // servername pair
                });
    }

    private byte[] servernamePairBytes;
    private byte[] serverName;
    private int serverNameLength;
    private byte serverType;

    public ServerNamePairParserTest(byte[] servernamePairBytes, byte[] serverName, int serverNameLength, byte serverType) {
        this.servernamePairBytes = servernamePairBytes;
        this.serverName = serverName;
        this.serverNameLength = serverNameLength;
        this.serverType = serverType;
    }

    /**
     * Test of parse method, of class ServerNamePairParser.
     */
    @Test
    public void testParse() {
        ServerNamePairParser parser = new ServerNamePairParser(0, servernamePairBytes);
        ServerNamePair pair = parser.parse();
        assertArrayEquals(serverName, pair.getServerName().getValue());
        assertTrue(serverNameLength == pair.getServerNameLength().getValue());
        assertTrue(serverType == pair.getServerNameType().getValue());
    }

}
