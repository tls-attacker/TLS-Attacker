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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.branchtree.ProbeVertex;


public class CountVertexTest {
    
    /**
     *
     */
    public CountVertexTest() {
    }
    
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
    @Before
    public void setUp() {
    }
    
    /**
     *
     */
    @After
    public void tearDown() {
    }

    // TODO add test methods here.
    // The methods must be annotated with annotation @Test. For example:
    //

    /**
     *
     */
        @Test
    public void testCountVertex() 
    {
        ProbeVertex vertex = new ProbeVertex(1);
        assertTrue("Failure: GetProbeID returend different ProbeID",vertex.getProbeID()==1);
      
        ProbeVertex vertex2 = new ProbeVertex(1);
   
        ProbeVertex vertex3 = new ProbeVertex(2);
        assertTrue("Failure: Vertices with the same ProbeID should equal",vertex.equals(vertex2));
        assertFalse("Failure: Vertices with different ProbeIDs should not be equal",vertex.equals(vertex3));
        
    }
    private static final Logger LOG = Logger.getLogger(CountVertexTest.class.getName());
}
