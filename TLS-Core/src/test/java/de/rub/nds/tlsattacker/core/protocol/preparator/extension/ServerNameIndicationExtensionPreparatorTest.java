/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class ServerNameIndicationExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                ServerNameIndicationExtensionMessage,
                ServerNameIndicationExtensionSerializer,
                ServerNameIndicationExtensionPreparator> {

    public ServerNameIndicationExtensionPreparatorTest() {
        super(
                ServerNameIndicationExtensionMessage::new,
                ServerNameIndicationExtensionSerializer::new,
                ServerNameIndicationExtensionPreparator::new);
    }

    /** Test of prepareExtensionContent method, of class ServerNameIndicationExtensionPreparator. */
    @Test
    public void testPrepare() {
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 1, new byte[] {0x01, 0x02});
        pairList.add(pair);
        context.getConfig().setDefaultSniHostnames(pairList);

        preparator.prepare();

        assertArrayEquals(
                new byte[] {0x01, 0x00, 0x02, 0x01, 0x02},
                preparator.getObject().getServerNameListBytes().getValue());
        assertEquals(5, preparator.getObject().getServerNameListLength().getOriginalValue());
    }

    @Test
    public void testPrepareWithTwoPairs() {
        List<ServerNamePair> pairList = new LinkedList<>();
        ServerNamePair pair = new ServerNamePair((byte) 1, new byte[] {0x01, 0x02});
        pairList.add(pair);
        ServerNamePair pair2 = new ServerNamePair((byte) 2, new byte[] {0x03, 0x04, 0x05, 0x06});
        pairList.add(pair2);
        context.getConfig().setDefaultSniHostnames(pairList);

        preparator.prepare();

        assertArrayEquals(
                new byte[] {0x01, 0x00, 0x02, 0x01, 0x02, 0x02, 0x00, 0x04, 0x03, 0x04, 0x05, 0x06},
                preparator.getObject().getServerNameListBytes().getValue());
        assertEquals(12, preparator.getObject().getServerNameListLength().getOriginalValue());
    }
}
