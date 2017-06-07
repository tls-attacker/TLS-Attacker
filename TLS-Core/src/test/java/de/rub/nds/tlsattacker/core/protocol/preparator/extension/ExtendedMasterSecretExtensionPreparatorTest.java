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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedMasterSecretExtensionSerializerTest;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import java.util.Collection;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
@RunWith(Parameterized.class)
public class ExtendedMasterSecretExtensionPreparatorTest {

    private final ExtensionType extensionType;
    private final int extensionLength;
    private final byte[] expectedBytes;
    private final int startParsing;
    private TlsContext context;
    private ExtendedMasterSecretExtensionMessage message;
    private ExtendedMasterSecretExtensionPreparator preparator;

    public ExtendedMasterSecretExtensionPreparatorTest(ExtensionType extensionType, int extensionLength,
            byte[] expectedBytes, int startParsing) {
        this.extensionType = extensionType;
        this.extensionLength = extensionLength;
        this.expectedBytes = expectedBytes;
        this.startParsing = startParsing;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> generateData() {
        return ExtendedMasterSecretExtensionSerializerTest.generateData();
    }

    @Test
    public void testPreparator() {
        context = new TlsContext();
        message = new ExtendedMasterSecretExtensionMessage();
        preparator = new ExtendedMasterSecretExtensionPreparator(context, message);

        context.getConfig().setAddExtendedMasterSecretExtension(true);
        preparator.prepare();

        assertArrayEquals(extensionType.getValue(), message.getExtensionType().getValue());
        assertEquals(extensionLength, (int) message.getExtensionLength().getValue());

    }

}
