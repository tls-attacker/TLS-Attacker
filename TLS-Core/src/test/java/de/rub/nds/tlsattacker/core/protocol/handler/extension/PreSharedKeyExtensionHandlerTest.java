/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class PreSharedKeyExtensionHandlerTest {

    private PreSharedKeyExtensionHandler handler;
    private TlsContext context;
    private PskSet pskSet1;
    private PskSet pskSet2;

    @Before
    public void setUp() {
        context = new TlsContext();

        pskSet1 = new PskSet(new byte[] { 0x00 }, new byte[] { 0x00 }, "0", new byte[] { 0x00 }, new byte[] { 0x00 },
            CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        pskSet2 = new PskSet(new byte[] { 0x01 }, new byte[] { 0x01 }, "1", new byte[] { 0x01 }, new byte[] { 0x01 },
            CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
        List<PskSet> pskSetList = new ArrayList<PskSet>();
        pskSetList.add(pskSet1);
        pskSetList.add(pskSet2);
        context.setPskSets(pskSetList);

        handler = new PreSharedKeyExtensionHandler(context);
    }

    @Test
    public void testadjustContext() {
        int selectedIdentity = 1;
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();
        msg.setSelectedIdentity(selectedIdentity);
        handler.adjustContext(msg);

        assertArrayEquals(context.getPsk(), pskSet2.getPreSharedKey());
        assertEquals(context.getSelectedIdentityIndex(), selectedIdentity);
    }

    @Test
    public void testadjustContextWithoutSelectedIdentity() {
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();
        handler.adjustContext(msg);

        assertArrayEquals(context.getEarlyDataPSKIdentity(), pskSet1.getPreSharedKeyIdentity());
        assertArrayEquals(context.getEarlyDataCipherSuite().getByteValue(), pskSet1.getCipherSuite().getByteValue());
    }

    @Test
    public void testadjustContextServerEndType() {
        context.setConnection(new InboundConnection());
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();

        PSKIdentity id1 = new PSKIdentity();
        PSKIdentity id2 = new PSKIdentity();
        id1.setIdentity(new byte[] { 0x03 });
        id2.setIdentity(new byte[] { 0x01 });

        List<PSKIdentity> identityList = new ArrayList<PSKIdentity>();
        identityList.add(id1);
        identityList.add(id2);
        msg.setIdentities(identityList);

        handler.adjustContext(msg);

        assertArrayEquals(context.getPsk(), pskSet2.getPreSharedKey());
        assertArrayEquals(context.getEarlyDataCipherSuite().getByteValue(), pskSet2.getCipherSuite().getByteValue());
        assertEquals(context.getSelectedIdentityIndex(), 1);
    }
}
