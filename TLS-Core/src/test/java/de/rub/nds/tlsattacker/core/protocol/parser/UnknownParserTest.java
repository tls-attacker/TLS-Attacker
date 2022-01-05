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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.UnknownMessage;
import java.io.ByteArrayInputStream;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

public class UnknownParserTest {

    private UnknownMessageParser parser;
    private final Config config = Config.createConfig();

    /**
     * Test of parse method, of class UnknownParser.
     */
    @Test
    public void testParse() {
        parser = new UnknownMessageParser(new ByteArrayInputStream(new byte[] { 0, 1, 2, 3 }), ProtocolVersion.TLS12,
            ProtocolMessageType.UNKNOWN, config);
        UnknownMessage message = new UnknownMessage();
        parser.parse(message);
        assertArrayEquals(new byte[] { 0, 1, 2, 3 }, message.getCompleteResultingMessage().getValue());
    }

}
