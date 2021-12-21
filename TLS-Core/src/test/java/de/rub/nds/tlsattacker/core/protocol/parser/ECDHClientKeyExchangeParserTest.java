/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class ECDHClientKeyExchangeParserTest {

    @SuppressWarnings("SpellCheckingInspection")
    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] { { ArrayConverter.hexStringToByteArray(
            "4104ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
            65,
            ArrayConverter.hexStringToByteArray(
                "04ccc0a7227daa353a64e0ba56cd98080c17901b744d9c747b12605874456d891200085d057014786df407ca391ada49c753f6c61486ad35eaf354580968dd991c"),
            ProtocolVersion.TLS12 },
            { ArrayConverter.hexStringToByteArray(
                "4104b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"),
                65,
                ArrayConverter.hexStringToByteArray(
                    "04b4b5b76d94709ec280af4f806b13e20e227e60d98a65204935e804076c829cd33ca5b7ff016584aeccc42a0b6db366cbb64a20af8c03ba6311a59552b3fad23e"),
                ProtocolVersion.TLS11 },
            { ArrayConverter.hexStringToByteArray(
                "41043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"),
                65,
                ArrayConverter.hexStringToByteArray(
                    "043775fe5c151587cc5b28958ea43b62ed642e02df9d6d58a17ac91756cbc8638ff5d22490ffc3e3abc144a5ecc5b54e84a576e7cd0df6863b35a55464e5038777"),
                ProtocolVersion.TLS10 } });
    }

    private byte[] message;

    private int serializedKeyLength;
    private byte[] serializedKey;
    private ProtocolVersion version;
    private final Config config = Config.createConfig();

    public ECDHClientKeyExchangeParserTest(byte[] message, int serializedKeyLength, byte[] serializedKey,
        ProtocolVersion version) {
        this.message = message;
        this.serializedKeyLength = serializedKeyLength;
        this.serializedKey = serializedKey;
        this.version = version;
    }

    /**
     * Test of parse method, of class ECDHClientKeyExchangeParser.
     */
    @Test
    public void testParse() {
        ECDHClientKeyExchangeParser<ECDHClientKeyExchangeMessage> parser =
            new ECDHClientKeyExchangeParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        ECDHClientKeyExchangeMessage msg = new ECDHClientKeyExchangeMessage();
        parser.parse(msg);
        assertTrue(serializedKeyLength == msg.getPublicKeyLength().getValue());
        assertArrayEquals(serializedKey, msg.getPublicKey().getValue());
    }

}
