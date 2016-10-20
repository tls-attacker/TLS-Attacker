package tlsattacker.fuzzer.graphs;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
import tlsattacker.fuzzer.graphs.Edge;
import tlsattacker.fuzzer.graphs.BranchTrace;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tlsattacker.fuzzer.result.MergeResult;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import static org.junit.Assert.assertTrue;

/**
 * 
 * @author ic0ns
 */
public class BranchTest {

    /**
     *
     */
    private static final Logger LOG = Logger.getLogger(BranchTest.class.getName());

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
    private BranchTrace tree;

    /**
     *
     */
    public BranchTest() {
	tree = new BranchTrace();
    }

    /**
     *
     */
    @Before
    public void setUp() {
	tree = new BranchTrace();
    }

    /**
     *
     */
    @After
    public void tearDown() {
	tree = null;
    }

    /**
     *
     */
    @Test
    public void testConstructor() {

	tree = new BranchTrace();
    }

    /**
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    @Test(expected = NullPointerException.class)
    public void testMergeNull() throws FileNotFoundException, IOException {
	tree.merge(null);
    }

    /**
     *
     */
    @Test
    public void testMerge() {
	Set<Long> verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	Map<Edge, Edge> edgeMap = new HashMap<>();
	Edge tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	BranchTrace trace = new BranchTrace(verticesSet, edgeMap);
	MergeResult mergeResult = tree.merge(trace);
	assertTrue(mergeResult.getHitVertices() == 3);
	assertTrue(mergeResult.getNewBranches() == 2);
	assertTrue(mergeResult.getNewVertices() == 3);
	verticesSet = new HashSet<>();
	verticesSet.add(1l);
	verticesSet.add(2l);
	verticesSet.add(3l);
	verticesSet.add(4l);

	edgeMap = new HashMap<>();
	tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	edgeMap.put(tempEdge, tempEdge);
	trace = new BranchTrace(verticesSet, edgeMap);
	mergeResult = tree.merge(trace);
	assertTrue(mergeResult.getHitVertices() == 4);
	assertTrue(mergeResult.getNewBranches() == 0);
	assertTrue(mergeResult.getNewVertices() == 1);
	verticesSet = new HashSet<>();
	edgeMap = new HashMap<>();
	tempEdge = new Edge(1, 2);
	edgeMap.put(tempEdge, tempEdge);
	tempEdge = new Edge(2, 3);
	tempEdge = new Edge(1, 3);

	edgeMap.put(tempEdge, tempEdge);
	trace = new BranchTrace(verticesSet, edgeMap);
	mergeResult = tree.merge(trace);
	assertTrue(mergeResult.getHitVertices() == 0);
	assertTrue(mergeResult.getNewBranches() == 1);
	assertTrue(mergeResult.getNewVertices() == 0);

    }
}
