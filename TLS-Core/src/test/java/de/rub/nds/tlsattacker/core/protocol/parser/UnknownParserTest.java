/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import static org.junit.Assert.*;
import org.junit.Test;

public class UnknownParserTest {

    private UnknownMessageParser parser;
    private final Config config = Config.createConfig();

    /**
     * Test of parse method, of class UnknownParser.
     */
    @Test
    public void testParse() {
        parser = new UnknownMessageParser(0, new byte[] { 0, 1, 2, 3 }, ProtocolVersion.TLS12,
            ProtocolMessageType.UNKNOWN, config);
        UnknownMessage message = parser.parse();
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
        parser = new UnknownMessageParser(1, new byte[] { 0, 1, 2, 3 }, ProtocolVersion.TLS12,
            ProtocolMessageType.UNKNOWN, config);
        message = parser.parse();
        assertArrayEquals(new byte[] { 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
    }

}
