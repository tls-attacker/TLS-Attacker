/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.ServerNameIndicationExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class ServerNameIndicationExtensionHandlerTest {

    private TlsContext context;
    private ServerNameIndicationExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new ServerNameIndicationExtensionHandler(context);
    }

    /**
     * Test of adjustTLSContext method, of class ServerNameIndicationExtensionHandler.
     */
    @Test
    public void testAdjustTLSContext() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair(NameType.HOST_NAME.getValue(), "localhost".getBytes());
        pair.setServerName(pair.getServerNameConfig());
        pair.setServerNameType(pair.getServerNameTypeConfig());
        pairList.add(pair);
        msg.setServerNameList(pairList);
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientSNIEntryList().size() == 1);
        SNIEntry entry = context.getClientSNIEntryList().get(0);
        assertEquals("localhost", entry.getName());
        assertTrue(entry.getType() == NameType.HOST_NAME);
    }

    @Test
    public void testUndefinedAdjustTLSContext() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 99, "localhost".getBytes());
        pair.setServerName(pair.getServerNameConfig());
        pair.setServerNameType(pair.getServerNameTypeConfig());
        pairList.add(pair);
        msg.setServerNameList(pairList);
        handler.adjustTLSContext(msg);
        assertTrue(context.getClientSNIEntryList().isEmpty());
    }

    /**
     * Test of getParser method, of class ServerNameIndicationExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[] { 0, 2, 3, }, 0,
            context.getConfig()) instanceof ServerNameIndicationExtensionParser);
    }

    /**
     * Test of getPreparator method, of class ServerNameIndicationExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(
            new ServerNameIndicationExtensionMessage()) instanceof ServerNameIndicationExtensionPreparator);
    }

    /**
     * Test of getSerializer method, of class ServerNameIndicationExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(
            new ServerNameIndicationExtensionMessage()) instanceof ServerNameIndicationExtensionSerializer);
    }

}
