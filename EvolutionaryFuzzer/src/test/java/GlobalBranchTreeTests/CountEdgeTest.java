/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package GlobalBranchTreeTests;

import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.branchtree.CountEdge;

/**
 * 
 * @author ic0ns
 */
public class CountEdgeTest {
    private static final Logger LOG = Logger.getLogger(CountEdgeTest.class.getName());

    /**
     *
     */
    @BeforeClass
    public static void setUpClass() {
    }

    /**
     *
     */
    @AfterClass
    public static void tearDownClass() {
    }

    /**
     *
     */
    public CountEdgeTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
    }

    /**
     *
     */
    @After
    public void tearDown() {
    }

    /**
     *
     */
    @Test
    public void testCountEdge() {
	CountEdge edge = new CountEdge();
	assertTrue("Failure: New generated Edges should have an EdgeCount of 1", edge.getCount() == 1);
	edge.increment();
	assertTrue("Failure: After Incrementing the Edgecount, the Edgecount should be 2", edge.getCount() == 2);
    }
}
