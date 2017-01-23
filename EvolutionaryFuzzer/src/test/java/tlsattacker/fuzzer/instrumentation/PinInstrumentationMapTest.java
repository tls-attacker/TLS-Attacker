/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.instrumentation;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import tlsattacker.fuzzer.result.MergeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PinInstrumentationMapTest {

    private PinInstrumentationMap map;
    private PinInstrumentationMap map2;

    public PinInstrumentationMapTest() {
    }

    @Before
    public void setUp() {
        Set<Long> codeblockSet = new HashSet<>();
        codeblockSet.add(1l);
        codeblockSet.add(2l);
        codeblockSet.add(3l);
        Map<Branch, Branch> branchMap = new HashMap<>();
        Branch tempBranch = new Branch(1, 2);
        branchMap.put(tempBranch, tempBranch);
        tempBranch = new Branch(2, 3);
        branchMap.put(tempBranch, tempBranch);
        map = new PinInstrumentationMap(codeblockSet, branchMap);
        codeblockSet = new HashSet<>();
        codeblockSet.add(1l);
        codeblockSet.add(4l);
        codeblockSet.add(3l);
        branchMap = new HashMap<>();
        tempBranch = new Branch(1, 4);
        branchMap.put(tempBranch, tempBranch);
        tempBranch = new Branch(4, 3);
        branchMap.put(tempBranch, tempBranch);
        map2 = new PinInstrumentationMap(codeblockSet, branchMap);

    }

    /**
     * Test of getCodeblocks method, of class PinInstrumentationMap.
     */
    @Test
    public void testGetCodeblocks() {
        assertTrue(map.getCodeblocks().size() == 3);
    }

    /**
     * Test of getBranches method, of class PinInstrumentationMap.
     */
    @Test
    public void testGetBranches() {
        assertTrue(map.getBranches().size() == 2);
    }

    /**
     * Test of didHitNew method, of class PinInstrumentationMap.
     */
    @Test
    public void testDidHitNew() {
        assertFalse(map.didHitNew(map));
        assertTrue(map.didHitNew(map2));
        assertTrue(map.didHitNew(map2));

    }

    /**
     * Test of merge method, of class PinInstrumentationMap.
     */
    @Test
    public void testMerge() {
        assertTrue(map.didHitNew(map2));
        map.merge(map2);
        assertFalse(map.didHitNew(map2));
    }

}
