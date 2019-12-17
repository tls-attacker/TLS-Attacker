/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ServerNameIndicationExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ServerNameIndicationExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;
import de.rub.nds.modifiablevariable.util.ArrayConverter;

//@RunWith(Parameterized.class)
public class ClientEsniInnerPreparatorTest {

    private Chooser chooser;
    private TlsContext context;

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        context = new TlsContext(config);
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, context, config);
    }

    @Before
    @Test
    public void test() {
        // Def Parameters:
        String hostName = "baz.example.com";
        byte nameType = (byte) 0x00;

        // Set Parameters:
        ClientEsniInner clientEsniInner = new ClientEsniInner();
        ClientEsniInnerPreparator clientEsniInnerPreparator = new ClientEsniInnerPreparator(chooser, clientEsniInner);

        ServerNamePair pair = new ServerNamePair();
        pair.setServerNameTypeConfig(nameType);
        pair.setServerNameConfig(hostName.getBytes(StandardCharsets.UTF_8));
        clientEsniInner.getServerNameList().add(pair);

        context.setEsniPaddedLength(260);
        // Compare results and expectations:
        clientEsniInnerPreparator.prepare();

        int resultNonceLength = clientEsniInner.getNonce().getValue().length;
        int expectedNonceLength = 16;

        int resultServerNameListLength = clientEsniInner.getServerNameListLength().getValue();
        int expectedServerNameListLength = 18;

        byte[] resultServerNameListBytes = clientEsniInner.getServerNameListBytes().getValue();
        byte[] expectedServerNameListBytes = ArrayConverter
                .hexStringToByteArray("00000f62617a2e6578616d706c652e636f6d");

        byte[] resultPadding = clientEsniInner.getPadding().getValue();
        byte[] expectedPadding = new byte[240];
        for (byte b : expectedPadding)
            b = (byte) 0x00;

        assertEquals(expectedNonceLength, resultNonceLength);
        assertEquals(expectedServerNameListLength, resultServerNameListLength);
        assertArrayEquals(expectedServerNameListBytes, resultServerNameListBytes);
        assertArrayEquals(expectedPadding, resultPadding);
    }
}