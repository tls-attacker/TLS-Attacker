/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

import java.util.LinkedList;
import java.util.List;

public class AlpnExtensionHandlerTest
    extends AbstractExtensionMessageHandlerTest<AlpnExtensionMessage, AlpnExtensionHandler> {

    private final byte[] announcedProtocols = ArrayConverter.hexStringToByteArray("02683208687474702f312e31");
    private final int announcedProtocolsLength = 12;

    public AlpnExtensionHandlerTest() {
        super(AlpnExtensionMessage::new, AlpnExtensionHandler::new);
    }

    @Test
    @Override
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
}
