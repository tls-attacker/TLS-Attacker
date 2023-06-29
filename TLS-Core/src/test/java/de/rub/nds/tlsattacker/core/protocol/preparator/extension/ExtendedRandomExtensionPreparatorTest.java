/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedRandomExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtendedRandomExtensionSerializer;
import org.junit.jupiter.api.Test;

public class ExtendedRandomExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                ExtendedRandomExtensionMessage,
                ExtendedRandomExtensionSerializer,
                ExtendedRandomExtensionPreparator> {

    private static final byte[] extendedRandomShort = new byte[0];
    private static final byte[] extendedRandom =
            ArrayConverter.hexStringToByteArray(
                    "AABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABBCCDDEEFFAABB");
    private static final byte[] extendedRandomLong =
            ArrayConverter.hexStringToByteArray(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                            + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    public ExtendedRandomExtensionPreparatorTest() {
        super(
                ExtendedRandomExtensionMessage::new,
                ExtendedRandomExtensionSerializer::new,
                ExtendedRandomExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandom);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandom);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(
                message.getExtendedRandomLength().getValue().intValue(), extendedRandom.length);
        assertArrayEquals(extendedRandom, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPrepareShort() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomShort);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandomShort);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(
                message.getExtendedRandomLength().getValue().intValue(),
                extendedRandomShort.length);
        assertArrayEquals(extendedRandomShort, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPrepareLong() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomLong);
        context.getConfig().setDefaultServerExtendedRandom(extendedRandomLong);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(
                message.getExtendedRandomLength().getValue().intValue(), extendedRandomLong.length);
        assertArrayEquals(extendedRandomLong, message.getExtendedRandom().getValue());
    }

    @Test
    public void testPrepareDefault() {
        context.getConfig().setAddExtendedRandomExtension(true);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(
                message.getExtendedRandomLength().getValue().intValue(),
                context.getConfig().getDefaultClientExtendedRandom().length);
        assertArrayEquals(
                context.getConfig().getDefaultClientExtendedRandom(),
                message.getExtendedRandom().getValue());
    }

    @Test
    public void testPrepareSameLengthRandom() {
        context.getConfig().setAddExtendedRandomExtension(true);
        context.getConfig().setDefaultClientExtendedRandom(extendedRandomLong);
        preparator.prepare();

        assertArrayEquals(
                ExtensionType.EXTENDED_RANDOM.getValue(), message.getExtensionType().getValue());
        assertEquals(
                message.getExtendedRandomLength().getValue().intValue(),
                context.getConfig().getDefaultClientExtendedRandom().length);
    }
}
