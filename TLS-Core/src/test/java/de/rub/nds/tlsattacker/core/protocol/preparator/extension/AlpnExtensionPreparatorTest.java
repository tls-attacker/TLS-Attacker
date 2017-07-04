/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class AlpnExtensionPreparatorTest {

    private TlsContext context;
    private AlpnExtensionPreparator preparator;
    private AlpnExtensionMessage msg;
    private final String announcedProtocols = "h2";
    private final int announcedProtocolsLength = 2;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new AlpnExtensionMessage();
        preparator = new AlpnExtensionPreparator(context, msg);
    }

    @Test
    public void testPreparator() {
        context.getConfig().setApplicationLayerProtocolNegotiationAnnouncedProtocols(announcedProtocols);

        preparator.prepare();

        assertArrayEquals(ExtensionType.ALPN.getValue(), msg.getExtensionType().getValue());
        assertEquals(announcedProtocolsLength, (int) msg.getAlpnExtensionLength().getValue());
        assertArrayEquals(announcedProtocols.getBytes(), msg.getAlpnAnnouncedProtocols().getValue());
    }

}
