
package GlobalBranchTreeTests;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.DirectedGraph;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.branchtree.Blocktype;
import tls.branchtree.BranchVertex;
import tls.branchtree.CountEdge;
import tls.branchtree.GlobalBranchTree;

/**
 *
 * @author ic0ns
 */
public class GlobalBranchTreeTest {
    private static final Logger LOG = Logger.getLogger(GlobalBranchTreeTest.class.getName());

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
    public GlobalBranchTreeTest() {
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
    @Ignore @Test
    public void testConnectedTree() {
        DirectedGraph<BranchVertex, CountEdge> g = GlobalBranchTree.buildGraph(new File("/home/ic0ns/Traces/TestCases/openssl.tree"));
        ConnectivityInspector inspector = new ConnectivityInspector(g);
        assertTrue("Failure: The GlobalBranchTree should be a connected Graph.",inspector.isGraphConnected());
    }
    */
    
    /**
    @Test
    public void TestValidTree() {
        DirectedGraph<BranchVertex, CountEdge> g = GlobalBranchTree.buildGraph(new File("/home/ic0ns/Traces/TestCases/openssl.tree"));

    }
    */
    /**
     *
     */
    @Test
    public void getVertex() {
        try
        {
            DirectedGraph<BranchVertex, CountEdge> graph = new DefaultDirectedGraph<>(CountEdge.class);
            graph.addVertex(new BranchVertex(0, Blocktype.RET, "a"));
            graph.addVertex(new BranchVertex(1, Blocktype.RET, "b"));
            graph.addVertex(new BranchVertex(2, Blocktype.RET, "c"));
            graph.addVertex(new BranchVertex(3, Blocktype.RET, "d"));
            graph.addVertex(new BranchVertex(4, Blocktype.RET, "e"));
            //search an existing vertex
            BranchVertex v = GlobalBranchTree.getVertex(3, graph);
            assertNotNull("Failure: Vertex with ProbeID 3 could not be found in the Graph",v);
            v = GlobalBranchTree.getVertex("b", graph);
            assertNotNull("Failure: Vertex with label b could not be found in the Graph",v);
            
            //search a non existant vertex
            v = GlobalBranchTree.getVertex(6, graph);
            assertNull("Failure: Should not return a Vertex that if the searched Vertex is not in the Graph, should return null instead",v);
            v = GlobalBranchTree.getVertex("aa", graph);
            assertNull("Failure: Should not return a Vertex that if the searched Vertex is not in the Graph, should return null instead",v);
        }
        catch (Exception ex)
        {
            
            Logger.getLogger(GlobalBranchTreeTest.class.getName()).log(Level.SEVERE, null, ex);
            fail("Failure: No Exception should be thrown when working with the GlobalBranchTree");
        }
    }
}
