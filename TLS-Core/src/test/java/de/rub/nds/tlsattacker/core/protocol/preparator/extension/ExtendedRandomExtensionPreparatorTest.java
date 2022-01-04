/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class ExtendedRandomExtensionPreparatorTest {

    private final byte[] extendedRandomShort = new byte[0];
    private final byte[] extendedRandom =
        ArrayConverter.hexStringToByteArray("AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
    private final byte[] extendedRandomLong =
        ArrayConverter.hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    private TlsContext context;
    private ExtendedRandomExtensionMessage message;
    private ExtendedRandomExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        message = new ExtendedRandomExtensionMessage();
        preparator = new ExtendedRandomExtensionPreparator(context.getChooser(), message,
            new ExtendedRandomExtensionSerializer(message));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandom);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandom);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(message.getExtendedRandomLength().getValue().intValue(), extendedRandom.length);
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPreparatorShort() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomShort);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandomShort);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(message.getExtendedRandomLength().getValue().intValue(), extendedRandomShort.length);
        assertArrayEquals(extendedRandomShort, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPreparatorLong() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomLong);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandomLong);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(message.getExtendedRandomLength().getValue().intValue(), extendedRandomLong.length);
        assertArrayEquals(extendedRandomLong, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPreparatorDefault() {
        context.getConfig().setAddExtendedRandomExtension(true);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(message.getExtendedRandomLength().getValue().intValue(),
            context.getConfig().getDefaultClientExtendedRandom().length);
        assertArrayEquals(context.getConfig().getDefaultClientExtendedRandom(), message.getExtendedRandom().getValue());

    }

    @Test
    public void testPrepareSameLengthRandom() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomLong);
        preparator.prepare();

        assertArrayEquals(ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(message.getExtendedRandomLength().getValue().intValue(),
            context.getConfig().getDefaultClientExtendedRandom().length);
    }

    @Test
    public void testNoContextPrepare() {
        preparator.prepare();
    }
}
