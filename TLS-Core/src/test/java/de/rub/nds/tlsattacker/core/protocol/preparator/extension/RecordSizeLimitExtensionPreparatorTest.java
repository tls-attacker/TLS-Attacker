/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ChooserType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.RecordSizeLimitExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.ChooserFactory;
import de.rub.nds.tlsattacker.core.workflow.chooser.DefaultChooser;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class RecordSizeLimitExtensionPreparatorTest {

    private Config config;
    private TlsContext context;
    private RecordSizeLimitExtensionPreparator preparator;
    private RecordSizeLimitExtensionMessage message;

    @Before
    public void setUp() {
        config = Config.createConfig();
        message = new RecordSizeLimitExtensionMessage();
    }

    /**
     * Test of prepare method, of class RecordSizeLimitExtensionPreparator.
     */
    @Test
    public void testPreparatorClient() {
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        context = new TlsContext(config);
        preparator =
            new RecordSizeLimitExtensionPreparator(ChooserFactory.getChooser(ChooserType.DEFAULT, context, config),
                message, new RecordSizeLimitExtensionSerializer(message));
        context.setClientRecordSizeLimit(1337);

        preparator.prepare();

        assertArrayEquals(new byte[] { (byte) 0x05, (byte) 0x39 }, message.getRecordSizeLimit().getValue());
        assertArrayEquals(ArrayConverter.intToBytes(context.getClientRecordSizeLimit(), 2),
            message.getRecordSizeLimit().getValue());
    }

    @Test
    public void testPreparatorServer() {
        config.setDefaultRunningMode(RunningModeType.SERVER);
        context = new TlsContext(config);
        preparator =
            new RecordSizeLimitExtensionPreparator(ChooserFactory.getChooser(ChooserType.DEFAULT, context, config),
                message, new RecordSizeLimitExtensionSerializer(message));
        context.setServerRecordSizeLimit(1337);

        preparator.prepare();

        assertArrayEquals(new byte[] { (byte) 0x05, (byte) 0x39 }, message.getRecordSizeLimit().getValue());
        assertArrayEquals(ArrayConverter.intToBytes(context.getServerRecordSizeLimit(), 2),
            message.getRecordSizeLimit().getValue());
    }
}
