/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ClientEsniInnerPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;

public class ClientEsniInnerSerializerTest {

    private Chooser chooser;
    private ClientEsniInner clientEsniInner;
    private ClientEsniInnerPreparator clientEsniInnerPreparator;
    private ClientEsniInnerSerializer clientEsniInnerSerializer;

    @Before
    public void setUp() {
        Config config = Config.createConfig();
        chooser = ChooserFactory.getChooser(ChooserType.DEFAULT, new TlsContext(config), config);
    }

    @Test
    public void test() {
        String hostname = "baz.example.com";
        byte nameType = (byte) 0x00;

        clientEsniInner = new ClientEsniInner();
        clientEsniInnerPreparator = new ClientEsniInnerPreparator(chooser, clientEsniInner);
        clientEsniInnerSerializer = new ClientEsniInnerSerializer(clientEsniInner);
        ServerNamePair pair = new ServerNamePair(nameType, hostname.getBytes(StandardCharsets.UTF_8));
        clientEsniInner.getServerNameList().add(pair);

        clientEsniInnerPreparator.prepare();
        byte[] resultBytes = clientEsniInnerSerializer.serialize();
        byte[] expectedBytes = ArrayConverter.hexStringToByteArray(
            "A7284C9A52F15C13644B947261774657001200000F62617A2E6578616D706C652E636F6D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        assertArrayEquals(expectedBytes, resultBytes);
    }
}
