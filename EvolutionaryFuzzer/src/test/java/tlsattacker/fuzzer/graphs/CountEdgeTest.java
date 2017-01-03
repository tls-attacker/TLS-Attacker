/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.graphs;

import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CountEdgeTest {

    @Test
    public void testCountEdge() {
        CountEdge edge = new CountEdge();
        assertTrue("Failure: New generated Edges should have an EdgeCount of 1", edge.getCount() == 1);
        edge.increment();
        assertTrue("Failure: After Incrementing the Edgecount, the Edgecount should be 2", edge.getCount() == 2);
    }
}
