/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import java.io.ByteArrayInputStream;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

abstract class AbstractExtensionMessageHandlerTest<
        MT extends ExtensionMessage, HT extends ExtensionHandler<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;

    protected HT handler;

    AbstractExtensionMessageHandlerTest(
            Supplier<MT> messageConstructor, Function<TlsContext, HT> handlerConstructor) {
        this(messageConstructor, handlerConstructor, TlsContext::new);
    }

    AbstractExtensionMessageHandlerTest(
            Supplier<MT> messageConstructor,
            Function<TlsContext, HT> handlerConstructor,
            Supplier<TlsContext> contextSupplier) {
        this.context = contextSupplier.get();
        this.messageConstructor = messageConstructor;
        this.handler = handlerConstructor.apply(context);
    }

    /** Test of getParser method, of class ExtensionHandler. */
    @Test
    public void testGetParser() {
        assertNotNull(
                messageConstructor.get().getParser(context, new ByteArrayInputStream(new byte[0])));
    }

    /** Test of getPreparator method, of class ExtensionHandler. */
    @Test
    public void testGetPreparator() {
        assertNotNull(messageConstructor.get().getPreparator(context));
    }

    /** Test of getSerializer method, of class ExtensionHandler. */
    @Test
    public void testGetSerializer() {
        assertNotNull(messageConstructor.get().getSerializer(context));
    }

    @Test
    public abstract void testadjustTLSExtensionContext();
}
