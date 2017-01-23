/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.instrumentation;

import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import tlsattacker.fuzzer.result.MergeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EmptyInstrumentationMapTest {

    private EmptyInstrumentationMap map;

    public EmptyInstrumentationMapTest() {
    }

    @Before
    public void setUp() {
        map = new EmptyInstrumentationMap();
    }

    /**
     * Test of getCodeblocks method, of class EmptyInstrumentationMap.
     */
    @Test
    public void testGetCodeblocks() {
        assertTrue(map.getCodeblocks().isEmpty());
    }

    /**
     * Test of getBranches method, of class EmptyInstrumentationMap.
     */
    @Test
    public void testGetBranches() {
        assertTrue(map.getBranches().isEmpty());
    }

    /**
     * Test of didHitNew method, of class EmptyInstrumentationMap.
     */
    @Test
    public void testDidHitNew() {
        assertFalse(map.didHitNew(null));
    }

    /**
     * Test of merge method, of class EmptyInstrumentationMap.
     */
    @Test
    public void testMerge() {
        MergeResult result = map.merge(null);
        assertTrue(result.getHitCodeblocks() == 0);
        assertTrue(result.getNewBranches() == 0);
        assertTrue(result.getNewCodeblocks() == 0);

    }

}
