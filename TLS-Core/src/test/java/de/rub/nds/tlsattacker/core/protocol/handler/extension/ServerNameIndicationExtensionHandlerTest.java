/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.NameType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.SNIEntry;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ServerNameIndicationExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                ServerNameIndicationExtensionMessage, ServerNameIndicationExtensionHandler> {

    public ServerNameIndicationExtensionHandlerTest() {
        super(ServerNameIndicationExtensionMessage::new, ServerNameIndicationExtensionHandler::new);
    }

    /** Test of adjustContext method, of class ServerNameIndicationExtensionHandler. */
    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair =
                new ServerNamePair(NameType.HOST_NAME.getValue(), "localhost".getBytes());
        pair.setServerName(pair.getServerNameConfig());
        pair.setServerNameType(pair.getServerNameTypeConfig());
        pairList.add(pair);
        msg.setServerNameList(pairList);
        handler.adjustTLSExtensionContext(msg);
        assertEquals(1, context.getClientSNIEntryList().size());
        SNIEntry entry = context.getClientSNIEntryList().get(0);
        assertEquals("localhost", entry.getName());
        assertSame(NameType.HOST_NAME, entry.getType());
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
