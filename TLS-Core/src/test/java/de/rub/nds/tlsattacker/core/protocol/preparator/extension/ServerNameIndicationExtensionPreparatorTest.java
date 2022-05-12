/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class ServerNameIndicationExtensionPreparatorTest {

    private Chooser chooser;
    private ServerNameIndicationExtensionMessage message;
    private ServerNameIndicationExtensionSerializer serializer;
    private Config config;

    @Before
    public void setUp() {
        config = Config.createConfig();
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, new TlsContext(config), config);
        message = new ServerNameIndicationExtensionMessage();
    }

    /**
     * Test of prepareExtensionContent method, of class ServerNameIndicationExtensionPreparator.
     */
    @Test
    public void testPrepareExtensionContentWithOnePair() {
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 1, new byte[] { 0x01, 0x02 });
        pairList.add(pair);
        config.setDefaultSniHostnames(pairList);
        ServerNameIndicationExtensionPreparator serverPrep =
            new ServerNameIndicationExtensionPreparator(chooser, message, serializer);

        serverPrep.prepareExtensionContent();

        assertArrayEquals(new byte[] { 0x01, 0x00, 0x02, 0x01, 0x02 },
            serverPrep.getObject().getServerNameListBytes().getValue());
        assertEquals(5, (long) serverPrep.getObject().getServerNameListLength().getOriginalValue());
    }

    @Test
    public void testPrepareExtensionContentWithTwoPairs() {
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 1, new byte[] { 0x01, 0x02 });
        pairList.add(pair);
        ServerNamePair pair2 = new ServerNamePair((byte) 2, new byte[] { 0x03, 0x04, 0x05, 0x06 });
        pairList.add(pair2);
        config.setDefaultSniHostnames(pairList);

        ServerNameIndicationExtensionPreparator serverPrep =
            new ServerNameIndicationExtensionPreparator(chooser, message, serializer);

        serverPrep.prepareExtensionContent();

        assertArrayEquals(new byte[] { 0x01, 0x00, 0x02, 0x01, 0x02, 0x02, 0x00, 0x04, 0x03, 0x04, 0x05, 0x06 },
            serverPrep.getObject().getServerNameListBytes().getValue());
        assertEquals(12, (long) serverPrep.getObject().getServerNameListLength().getOriginalValue());
    }
}
