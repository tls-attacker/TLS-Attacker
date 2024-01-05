/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.extension.PreSharedKeyExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PSKIdentity;
import de.rub.nds.tlsattacker.core.protocol.message.extension.psk.PskSet;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class PreSharedKeyExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                PreSharedKeyExtensionMessage, PreSharedKeyExtensionHandler> {

    private final PskSet pskSet1;
    private final PskSet pskSet2;

    public PreSharedKeyExtensionHandlerTest() {
        super(PreSharedKeyExtensionMessage::new, PreSharedKeyExtensionHandler::new);
        pskSet1 =
                new PskSet(
                        new byte[] {0x00},
                        new byte[] {0x00},
                        "0",
                        new byte[] {0x00},
                        new byte[] {0x00},
                        CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA);
        pskSet2 =
                new PskSet(
                        new byte[] {0x01},
                        new byte[] {0x01},
                        "1",
                        new byte[] {0x01},
                        new byte[] {0x01},
                        CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA);
        List<PskSet> pskSetList = new ArrayList<>();
        pskSetList.add(pskSet1);
        pskSetList.add(pskSet2);
        context.setPskSets(pskSetList);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        int selectedIdentity = 1;
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();
        msg.setSelectedIdentity(selectedIdentity);
        handler.adjustContext(msg);

        assertArrayEquals(pskSet2.getPreSharedKey(), context.getPsk());
        assertEquals(selectedIdentity, context.getSelectedIdentityIndex());
    }

    @Test
    public void testadjustContextWithoutSelectedIdentity() {
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();
        handler.adjustContext(msg);

        assertArrayEquals(pskSet1.getPreSharedKeyIdentity(), context.getEarlyDataPSKIdentity());
        assertArrayEquals(
                pskSet1.getCipherSuite().getByteValue(),
                context.getEarlyDataCipherSuite().getByteValue());
    }

    @Test
    public void testadjustContextServerEndType() {
        context.getContext().setConnection(new InboundConnection());
        PreSharedKeyExtensionMessage msg = new PreSharedKeyExtensionMessage();

        PSKIdentity id1 = new PSKIdentity();
        PSKIdentity id2 = new PSKIdentity();
        id1.setIdentity(new byte[] {0x03});
        id2.setIdentity(new byte[] {0x01});

        List<PSKIdentity> identityList = new ArrayList<>();
        identityList.add(id1);
        identityList.add(id2);
        msg.setIdentities(identityList);

        handler.adjustContext(msg);

        assertArrayEquals(pskSet2.getPreSharedKey(), context.getPsk());
        assertArrayEquals(
                pskSet2.getCipherSuite().getByteValue(),
                context.getEarlyDataCipherSuite().getByteValue());
        assertEquals(1, context.getSelectedIdentityIndex());
    }
}
