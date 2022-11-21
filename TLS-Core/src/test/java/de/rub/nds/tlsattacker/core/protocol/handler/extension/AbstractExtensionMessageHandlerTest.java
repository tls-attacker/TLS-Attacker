/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.junit.jupiter.api.Test;

import java.util.function.Function;
import java.util.function.Supplier;

abstract class AbstractExtensionMessageHandlerTest<MT extends ExtensionMessage, HT extends ExtensionHandler<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;

    protected HT handler;

    AbstractExtensionMessageHandlerTest(Supplier<MT> messageConstructor, Function<TlsContext, HT> handlerConstructor) {
        this(messageConstructor, handlerConstructor, TlsContext::new);
    }

    AbstractExtensionMessageHandlerTest(Supplier<MT> messageConstructor, Function<TlsContext, HT> handlerConstructor,
        Supplier<TlsContext> contextSupplier) {
        this.context = contextSupplier.get();
        this.messageConstructor = messageConstructor;
        this.handler = handlerConstructor.apply(context);
    }

    /**
     * Test of getParser method, of class ExtensionHandler.
     */
    @Test
    public void testGetParser() {
        assertNotNull(handler.getParser(new byte[0], 0, context.getConfig()));
    }

    /**
     * Test of getPreparator method, of class ExtensionHandler.
     */
    @Test
    public void testGetPreparator() {
        assertNotNull(handler.getPreparator(messageConstructor.get()));
    }

    /**
     * Test of getSerializer method, of class ExtensionHandler.
     */
    @Test
    public void testGetSerializer() {
        assertNotNull(handler.getSerializer(messageConstructor.get()));
    }

    @Test
    public abstract void testAdjustTLSContext();
}
