/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.https;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.Arrays;
import java.util.Collection;
import static org.junit.Assert.*;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class HttpsResponseSerializerTest {

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return Arrays
                .asList(new Object[][] { {
                        ArrayConverter
                                .hexStringToByteArray("485454502f312e3120323030204f4b0d0a486f73743a207275622e636f6d0d0a436f6e74656e742d547970653a20746578742f68746d6c0d0a0d0a64617461"),
                        ProtocolVersion.TLS12,
                        ArrayConverter
                                .hexStringToByteArray("485454502F312E3120323030204F4B0D0A0D0A486F73743A207275622E636F6D0D0A436F6E74656E742D547970653A20746578742F68746D6C0D0A0D0A64617461") } });
    }

    private final byte[] msg;
    private final ProtocolVersion version;
    private final byte[] expPart;

    public HttpsResponseSerializerTest(byte[] msg, ProtocolVersion version, byte[] expPart) {
        this.msg = msg;
        this.version = version;
        this.expPart = expPart;
    }

    /**
     * Test of serializeProtocolMessageContent method, of class
     * HttpsResponseSerializer.
     */
    @Test
    public void testSerializeProtocolMessageContent() {
        HttpsResponseParser parser = new HttpsResponseParser(0, msg, version);
        HttpsResponseMessage parsedMsg = parser.parse();
        HttpsResponseSerializer serializer = new HttpsResponseSerializer(parsedMsg, version);

        assertArrayEquals(expPart, serializer.serialize());
    }

}