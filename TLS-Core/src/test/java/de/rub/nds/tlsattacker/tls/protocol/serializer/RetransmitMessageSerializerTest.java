/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.message.RetransmitMessage;
import de.rub.nds.tlsattacker.tls.protocol.parser.AlertParserTest;
import de.rub.nds.tlsattacker.tls.protocol.preparator.RetransmitMessagePreparator;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import java.util.Collection;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class RetransmitMessageSerializerTest {

    private RetransmitMessageSerializer serializer;
    private RetransmitMessage msg;

    public RetransmitMessageSerializerTest() {
    }

    @Before
    public void setUp() {
        msg = new RetransmitMessage(new byte[] { 6, 6, 6 });
        serializer = new RetransmitMessageSerializer(msg, ProtocolVersion.TLS12);
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * RetransmitMessageSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        RetransmitMessagePreparator preparator = new RetransmitMessagePreparator(new TlsContext(), msg);
        preparator.prepare();
        assertArrayEquals(new byte[] { 6, 6, 6 }, serializer.serialize());
    }
}
