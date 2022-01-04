/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.PskEcDhClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class PskEcDhClientKeyExchangeParserTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays.asList(new Object[][] {
            { ArrayConverter.hexStringToByteArray(
                "000f436c69656e745f6964656e7469747920f73171f4379e1897f443a82bcc06d79368f96aad699f10d21505c661fe80655b"),
                ProtocolVersion.TLS12 },
            { ArrayConverter.hexStringToByteArray(
                "000f436c69656e745f6964656e746974792073f7cf3676cef0cf08b800519732540c8a16062aa5e24fc2360007c265b83f1b"),
                ProtocolVersion.TLS12 } });
    }

    private final byte[] message;
    private final ProtocolVersion version;
    private final Config config = Config.createConfig();

    public PskEcDhClientKeyExchangeParserTest(byte[] message, ProtocolVersion version) {
        this.message = message;
        this.version = version;
    }

    @Test
    public void testParse() {
        PskEcDhClientKeyExchangeParser parser =
            new PskEcDhClientKeyExchangeParser(new ByteArrayInputStream(message), version, new TlsContext(config));
        PskEcDhClientKeyExchangeMessage msg = new PskEcDhClientKeyExchangeMessage();
        parser.parse(msg);
    }

}
