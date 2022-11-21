/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.commons.lang3.function.TriFunction;
import org.junit.jupiter.api.Test;

import java.util.function.Function;
import java.util.function.Supplier;

abstract class AbstractExtensionMessagePreparatorTest<MT extends ExtensionMessage, ST extends ExtensionSerializer<MT>,
    PT extends ExtensionPreparator<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;
    private final Function<Config, MT> messageConstructorWithConfig;
    protected MT message;

    private final Function<MT, ST> serializerConstructor;

    private final TriFunction<Chooser, MT, ST, PT> preparatorConstructor;
    protected PT preparator;

    AbstractExtensionMessagePreparatorTest(Supplier<MT> messageConstructor,
        Function<Config, MT> messageConstructorWithConfig, Function<MT, ST> serializerConstructor,
        TriFunction<Chooser, MT, ST, PT> preparatorConstructor) {
        this.context = new TlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = messageConstructorWithConfig;
        this.serializerConstructor = serializerConstructor;
        this.preparatorConstructor = preparatorConstructor;
        createNewMessageAndPreparator();
    }

    @Test
    public abstract void testPrepare() throws Exception;

    @Test
    public void testPrepareNoContext() {
        assertDoesNotThrow(preparator::prepare);
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
        preparator = preparatorConstructor.apply(context.getChooser(), message, serializerConstructor.apply(message));
    }
}
