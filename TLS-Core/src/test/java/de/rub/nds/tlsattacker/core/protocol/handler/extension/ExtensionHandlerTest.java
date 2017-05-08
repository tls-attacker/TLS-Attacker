/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Matthias Terlinde <matthias.terlinde@rub.de>
 */
public abstract class ExtensionHandlerTest {

    protected ExtensionHandler handler;

    protected TlsContext context;

    @Before
    public abstract void setUp();

    @Test
    public abstract void testAdjustTLSContext();

    @Test
    public abstract void testGetParser();

    @Test
    public abstract void testGetPreparator();

    @Test
    public abstract void testGetSerializer();

}
