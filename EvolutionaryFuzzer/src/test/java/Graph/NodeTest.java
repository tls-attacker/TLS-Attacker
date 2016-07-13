/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package Graph;

import Graphs.Node;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @author ic0ns
 */
public class NodeTest {
    private static final Logger LOG = Logger.getLogger(NodeTest.class.getName());

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

    Node<Object> node = null;

    /**
     *
     */
    public NodeTest() {
    }

    /**
     *
     */
    @Before
    public void setUp() {
	node = new Node<>(new Object());
    }

    /**
     *
     */
    @After
    public void tearDown() {
	node = null;
    }

    /**
     *
     */
    @Test
    public void testConstructor() {
	node = new Node<>(null);

    }

    /**
     *
     */
    @Test
    public void testAddGetChild() {
	Node<Object> node2 = new Node<>(new Object());
	Node<Object> node3 = new Node<>(new Object());

	node.addChild(node2);
	node.addChild(node3);
	assertTrue("Failure: After adding 2 Children the Children List should contain 2 Elements", node.getChildren()
		.size() == 2);
	Node<Object> n = node.getChildren().get(0);
	assertTrue("Failure: Could not retrieve the first Child", n == node2);

    }

    /**
     *
     */
    @Test(expected = NullPointerException.class)
    public void testAddNullChild() {
	node.addChild(null);
    }

    /**
     *
     */
    @Test
    public void testGetData() {
	Node<Integer> n = new Node<>(1);
	assertTrue("Failure: Date in Constructor does not equal the Data received from the getData method", n.getData()
		.equals(1));
    }

    /**
     *
     */
    @Test
    public void testParent() {

	Node<Object> node2 = new Node<>(new Object());
	node.addChild(node2);
	Node<Object> node3 = node2.getParent();
	assertNotNull("Failure: The Parent was not Set correctly, recieved a null Parent", node3);
	assertEquals("Failure: Recieved Parent and Real Parent are not equal", node3, node);

    }

}
