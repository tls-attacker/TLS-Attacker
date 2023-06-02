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

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ClientEsniInnerPreparatorTest {

    private TlsContext context;

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    @Test
    public void testPrepare() {
        String hostName = "baz.example.com";
        byte nameType = (byte) 0x00;

        ClientEsniInner clientEsniInner = new ClientEsniInner();
        ClientEsniInnerPreparator clientEsniInnerPreparator =
                new ClientEsniInnerPreparator(context.getChooser(), clientEsniInner);
        ServerNamePair pair =
                new ServerNamePair(nameType, hostName.getBytes(StandardCharsets.UTF_8));
        clientEsniInner.getServerNameList().add(pair);
        context.setEsniPaddedLength(260);

        clientEsniInnerPreparator.prepare();
        int resultNonceLength = clientEsniInner.getClientNonce().getValue().length;
        int expectedNonceLength = 16;
        int resultServerNameListLength = clientEsniInner.getServerNameListLength().getValue();
        int expectedServerNameListLength = 18;
        byte[] resultServerNameListBytes = clientEsniInner.getServerNameListBytes().getValue();
        byte[] expectedServerNameListBytes =
                ArrayConverter.hexStringToByteArray("00000f62617a2e6578616d706c652e636f6d");
        byte[] resultPadding = clientEsniInner.getPadding().getValue();
        byte[] expectedPadding = new byte[240];

        assertEquals(expectedNonceLength, resultNonceLength);
        assertEquals(expectedServerNameListLength, resultServerNameListLength);
        assertArrayEquals(expectedServerNameListBytes, resultServerNameListBytes);
        assertArrayEquals(expectedPadding, resultPadding);
    }
}
