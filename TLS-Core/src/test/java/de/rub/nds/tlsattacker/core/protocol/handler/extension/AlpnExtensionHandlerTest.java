/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.AlpnExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class AlpnExtensionHandlerTest {

    private final byte[] announcedProtocols = ArrayConverter.hexStringToByteArray("02683208687474702f312e31");
    private final int announcedProtocolsLength = 12;
    private AlpnExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new AlpnExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        AlpnExtensionMessage msg = new AlpnExtensionMessage();
        msg.setProposedAlpnProtocolsLength(announcedProtocolsLength);
        msg.setProposedAlpnProtocols(announcedProtocols);
        List<AlpnEntry> alpnEntryList = new LinkedList<>();
        alpnEntryList.add(new AlpnEntry(new String(announcedProtocols)));
        alpnEntryList.get(0).setAlpnEntry(new String(announcedProtocols));
        msg.setAlpnEntryList(alpnEntryList);
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        handler.adjustTLSContext(msg);
        List<String> alpnStringList = new LinkedList<>();
        alpnStringList.add(new String(announcedProtocols));
        assertEquals(alpnStringList, context.getProposedAlpnProtocols());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0, context.getConfig()) instanceof AlpnExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new AlpnExtensionMessage()) instanceof AlpnExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new AlpnExtensionMessage()) instanceof AlpnExtensionSerializer);
    }
}
