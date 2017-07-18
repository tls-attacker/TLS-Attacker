/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RenegotiationInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public class RenegotiationInfoExtensionPreparatorTest {

    private final int extensionLength = 1;
    private final byte[] extensionPayload = new byte[] { 0 };
    private TlsContext context;
    private RenegotiationInfoExtensionMessage message;
    private RenegotiationInfoExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new RenegotiationInfoExtensionMessage();
        preparator = new RenegotiationInfoExtensionPreparator(context.getChooser(),
                (RenegotiationInfoExtensionMessage) message);

    }

    @Test
    public void testPreparator() {
        context.getConfig().setDefaultRenegotiationInfo(extensionPayload);
        preparator.prepare();

        assertArrayEquals(ExtensionType.RENEGOTIATION_INFO.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (long) message.getExtensionLength().getValue());
        assertArrayEquals(extensionPayload, message.getRenegotiationInfo().getValue());
    }

}
