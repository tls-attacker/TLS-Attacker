/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessagePreparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

abstract class AbstractProtocolMessagePreparatorTest<
        MT extends ProtocolMessage, PT extends ProtocolMessagePreparator<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;
    private final Function<Config, MT> messageConstructorWithConfig;
    protected MT message;

    private final BiFunction<Chooser, MT, PT> preparatorConstructor;
    protected PT preparator;

    AbstractProtocolMessagePreparatorTest(
            Supplier<MT> messageConstructor,
            Function<Config, MT> messageConstructorWithConfig,
            BiFunction<Chooser, MT, PT> preparatorConstructor) {
        this.context = new TlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = messageConstructorWithConfig;
        this.preparatorConstructor = preparatorConstructor;
        createNewMessageAndPreparator();
    }

    AbstractProtocolMessagePreparatorTest(
            Supplier<MT> messageConstructor, BiFunction<Chooser, MT, PT> preparatorConstructor) {
        this.context = new TlsContext();
        this.messageConstructor = messageConstructor;
        this.messageConstructorWithConfig = null;
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
        preparator = preparatorConstructor.apply(context.getChooser(), message);
    }
}
