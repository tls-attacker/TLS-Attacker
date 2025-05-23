/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Test;

abstract class AbstractExtensionMessagePreparatorTest<
        MT extends ExtensionMessage,
        ST extends ExtensionSerializer<MT>,
        PT extends ExtensionPreparator<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;
    private final Function<Config, MT> messageConstructorWithConfig;
    protected MT message;

    private final Function<MT, ST> serializerConstructor;

    private final TriFunction<Chooser, MT, ST, PT> preparatorConstructorWithSerializer;
    private final BiFunction<Chooser, MT, PT> preparatorConstructor;
    protected PT preparator;

    AbstractExtensionMessagePreparatorTest(
            Supplier<MT> messageConstructor,
            Function<Config, MT> messageConstructorWithConfig,
            Function<MT, ST> serializerConstructor,
            TriFunction<Chooser, MT, ST, PT> preparatorConstructorWithSerializer) {
        this.context =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = messageConstructorWithConfig;
        this.serializerConstructor = serializerConstructor;
        this.preparatorConstructor = null;
        this.preparatorConstructorWithSerializer = preparatorConstructorWithSerializer;
        createNewMessageAndPreparator();
    }

    AbstractExtensionMessagePreparatorTest(
            Supplier<MT> messageConstructor,
            Function<MT, ST> serializerConstructor,
            BiFunction<Chooser, MT, PT> preparatorConstructor) {
        this.context =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = null;
        this.serializerConstructor = serializerConstructor;
        this.preparatorConstructor = preparatorConstructor;
        this.preparatorConstructorWithSerializer = null;
        createNewMessageAndPreparator();
    }

    AbstractExtensionMessagePreparatorTest(
            Supplier<MT> messageConstructor,
            Function<MT, ST> serializerConstructor,
            TriFunction<Chooser, MT, ST, PT> preparatorConstructorWithConfig) {
        this.context =
                new Context(new State(new Config()), new InboundConnection()).getTlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = null;
        this.serializerConstructor = serializerConstructor;
        this.preparatorConstructor = null;
        this.preparatorConstructorWithSerializer = preparatorConstructorWithConfig;
        createNewMessageAndPreparator();
    }

    @Test
    public abstract void testPrepare() throws Exception;

    @Test
    public void testPrepareNoContext() {
        assertDoesNotThrow(preparator::prepare);
    }

    @Test
    public void testWithExplicitContentModification() {
        byte[] explicitContent = new byte[] {0x01, 0x02, 0x03};
        message.setExtensionContent(Modifiable.explicit(explicitContent));
        preparator.prepare();
        assertEquals(
                explicitContent.length,
                (int) message.getExtensionLength().getValue(),
                "Extension length does not respect explicit extension content");
    }

    protected void createNewMessageAndPreparator() {
        createNewMessageAndPreparator(false);
    }

    protected void createNewMessageAndPreparator(boolean includeConfigInMessageConstructor) {
        if (includeConfigInMessageConstructor) {
            message = messageConstructorWithConfig.apply(context.getConfig());
        } else {
            message = messageConstructor.get();
        }
        if (preparatorConstructorWithSerializer != null) {
            preparator =
                    preparatorConstructorWithSerializer.apply(
                            context.getChooser(), message, serializerConstructor.apply(message));
        } else {
            preparator = preparatorConstructor.apply(context.getChooser(), message);
        }
    }
}
