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
public class AFLInstrumentationMapTest {

    private AFLInstrumentationMap map1;
    private AFLInstrumentationMap map2;

    public AFLInstrumentationMapTest() {
    }

    @Before
    public void setUp() {
        long[] bitmap1 = new long[4];
        long[] bitmap2 = new long[4];
        bitmap1[0] = 5;
        bitmap1[1] = 1;
        bitmap2[1] = 4;
        bitmap2[3] = 2;
        map1 = new AFLInstrumentationMap(bitmap1);
        map2 = new AFLInstrumentationMap(bitmap2);

    }

    /**
     * Test of getCodeblocks method, of class AFLInstrumentationMap.
     */
    @Test
    public void testGetCodeblocks() {
        assertTrue(map1.getCodeblocks().isEmpty());
    }

    /**
     * Test of getBranches method, of class AFLInstrumentationMap.
     */
    @Test
    public void testGetBranches() {
        assertTrue(map1.getBranches().isEmpty());
    }

    /**
     * Test of didHitNew method, of class AFLInstrumentationMap.
     */
    @Test
    public void testDidHitNew() {
        assertFalse(map1.didHitNew(map1));
        assertTrue(map1.didHitNew(map2));
        assertTrue(map2.didHitNew(map1));
    }

    /**
     * Test of merge method, of class AFLInstrumentationMap.
     */
    @Test
    public void testMerge() {
        map1.merge(map2);
        assertFalse(map2.didHitNew(map1));
        assertTrue(map1.didHitNew(map2));
    }

}
