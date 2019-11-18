/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Test;

public class ResponderIdSerializerTest {

    private final byte[] expectedBytes = new byte[] { 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    private final ResponderId id = new ResponderId(5, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });

    @Test
    public void testSerializer() {
        ResponderIdPreparator preparator = new ResponderIdPreparator(new TlsContext().getChooser(), id);
        preparator.prepare();
        ResponderIdSerializer serializer = new ResponderIdSerializer(id);

        assertArrayEquals(expectedBytes, serializer.serialize());
    }
}
