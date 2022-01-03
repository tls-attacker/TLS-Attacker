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
     * Test of adjustContext method, of class ServerNameIndicationExtensionHandler.
     */
    @Test
    public void testadjustContext() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair(NameType.HOST_NAME.getValue(), "localhost".getBytes());
        pair.setServerName(pair.getServerNameConfig());
        pair.setServerNameType(pair.getServerNameTypeConfig());
        pairList.add(pair);
        msg.setServerNameList(pairList);
        handler.adjustContext(msg);
        assertTrue(context.getClientSNIEntryList().size() == 1);
        SNIEntry entry = context.getClientSNIEntryList().get(0);
        assertEquals("localhost", entry.getName());
        assertTrue(entry.getType() == NameType.HOST_NAME);
    }

    @Test
    public void testUndefinedadjustContext() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 99, "localhost".getBytes());
        pair.setServerName(pair.getServerNameConfig());
        pair.setServerNameType(pair.getServerNameTypeConfig());
        pairList.add(pair);
        msg.setServerNameList(pairList);
        handler.adjustContext(msg);
        assertTrue(context.getClientSNIEntryList().isEmpty());
    }
}
