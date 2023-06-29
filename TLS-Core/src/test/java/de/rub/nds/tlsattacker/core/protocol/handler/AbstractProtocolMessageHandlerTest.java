/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;
import java.io.ByteArrayInputStream;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

abstract class AbstractProtocolMessageHandlerTest<
        MT extends ProtocolMessage<?>, HT extends ProtocolMessageHandler<MT>> {

    protected TlsContext context;

    private final Supplier<MT> messageConstructor;

    protected HT handler;

    AbstractProtocolMessageHandlerTest(
            Supplier<MT> messageConstructor, Function<TlsContext, HT> handlerConstructor) {
        this.context = new TlsContext();
        this.messageConstructor = messageConstructor;
        this.handler = handlerConstructor.apply(context);
    }

    /** Test of getParser method, of class TlsMessageHandler. */
    @Test
    public void testGetParser() {
        assertNotNull(
                messageConstructor.get().getParser(context, new ByteArrayInputStream(new byte[0])));
    }

    /** Test of getPreparator method, of class TlsMessageHandler. */
    @Test
    public void testGetPreparator() {
        assertNotNull(messageConstructor.get().getPreparator(context));
    }

    /** Test of getSerializer method, of class TlsMessageHandler. */
    @Test
    public void testGetSerializer() {
        assertNotNull(messageConstructor.get().getSerializer(context));
    }

    @Test
    public abstract void testadjustContext();
}
