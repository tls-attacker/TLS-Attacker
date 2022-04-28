/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class SignatureAndHashAlgorithmsExtensionParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { {
            ArrayConverter.hexStringToByteArray("001e060106020603050105020503040104020403030103020303020102020203"), 30,
            ArrayConverter.hexStringToByteArray("060106020603050105020503040104020403030103020303020102020203") } });
    }

    private byte[] extension;
    private int algoListLength;
    private byte[] algoList;
    private final Config config = Config.createConfig();

    public SignatureAndHashAlgorithmsExtensionParserTest(byte[] extension, int algoListLength, byte[] algoList) {
        this.extension = extension;
        this.algoListLength = algoListLength;
        this.algoList = algoList;
    }

    /**
     * Test of parse method, of class SignatureAndHashAlgorithmsExtensionParser.
     */
    @Test
    public void testParse() {
        TlsContext tlsContext = new TlsContext(config);
        SignatureAndHashAlgorithmsExtensionParser parser =
            new SignatureAndHashAlgorithmsExtensionParser(new ByteArrayInputStream(extension), tlsContext);
        SignatureAndHashAlgorithmsExtensionMessage msg = new SignatureAndHashAlgorithmsExtensionMessage();
        parser.parse(msg);
        assertArrayEquals(msg.getSignatureAndHashAlgorithms().getValue(), algoList);
        assertTrue(algoListLength == msg.getSignatureAndHashAlgorithmsLength().getValue());
    }
}
