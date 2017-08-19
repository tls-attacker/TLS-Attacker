/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.util.Map;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 *
 * @author Lucas Hartmann <lucas.hartmann@rub.de>
 */
public class StateTest {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    /**
     * Check if parameterless initialization behaves properly.
     */
    @Test
    public void testInit() {
        State s = new State();
        assertNotNull(s.getTlsContext());
        assertTrue(s.getTlsContexts().size() == 1);
        assertNotNull(s.getConfig());
    }

    /**
     * Be thorough with the context map and make sure that it can only be
     * modified via methods provided by State.
     */
    @Test
    public void testImmutableContextList() {
        State s = new State();
        TlsContext c1 = new TlsContext();
        TlsContext c2 = new TlsContext();

        s.addTlsContext("ctx1", c1);
        Map<String, TlsContext> cMap = s.getTlsContexts();
        exception.expect(UnsupportedOperationException.class);
        cMap.put("ctx2", c2);
    }

    /**
     * Assure that aliases are unique.
     */
    @Test
    public void testGetContextDuplicateAlias() {
        State s = new State();
        TlsContext c = new TlsContext();
        String alias = "alias";

        s.addTlsContext(alias, c);
        exception.expect(ConfigurationException.class);
        exception.expectMessage("Alias already in use");
        s.addTlsContext(alias, c);
    }

    /**
     * Prevent accidental misuse of single/default context getter. If multiple
     * contexts are defined, require the user to give us an alias to get the
     * appropriate context.
     */
    @Test
    public void testGetContextAliasRequired() {
        State s = new State();
        TlsContext c1 = new TlsContext();
        TlsContext c2 = new TlsContext();

        s.addTlsContext("ctx1", c1);
        s.addTlsContext("ctx2", c2);
        exception.expect(ConfigurationException.class);
        exception.expectMessage("getTlsContext requires an alias if multiple contexts are defined");
        c1 = s.getTlsContext();
    }

}
