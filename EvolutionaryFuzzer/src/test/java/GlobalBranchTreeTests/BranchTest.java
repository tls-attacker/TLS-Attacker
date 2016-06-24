package GlobalBranchTreeTests;

/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import tls.branchtree.BranchTrace;
import tls.branchtree.MergeResult;


public class BranchTest {

    /**
     *
     */
    @BeforeClass
    public static void setUpClass()
    {
    }

    /**
     *
     */
    @AfterClass
    public static void tearDownClass()
    {
    }

    private BranchTrace tree;

    //TODO Filenames from testcases

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
        //Test with null
        tree.merge(null);
    }

    /**
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    @Test(expected = FileNotFoundException.class)
    public void testMergeNotExistentFile() throws FileNotFoundException, IOException {
        tree.merge(new File("../resources/testsuite/EvolutionaryFuzzer/BranchTest/openssl"));
        tree.merge(new File(""));
    }

    /**
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    @Test(expected = NumberFormatException.class)
    public void testMergeInvalid() throws FileNotFoundException, IOException {
        tree.merge(new File("../resources/testsuite/EvolutionaryFuzzer/BranchTest/openssl3"));
    }

    /**
     *
     */
    @Test
    public void testMergeValid() {
        //Test with valid
        Exception e = null;
        try
        {
            tree.merge(new File("../resources/testsuite/EvolutionaryFuzzer/BranchTest/openssl"));
            MergeResult r = tree.merge(new File("../resources/testsuite/EvolutionaryFuzzer/BranchTest/openssl2"));
            assertTrue("Failure: The Test File contains exactly 2 new Branches, we found:"+r.getNewBranches(),r.getNewBranches() == 2);
            assertTrue("Failure: The Test File contains exactly 1 new Vertice, we found:"+r.getNewVertices(),r.getNewVertices()== 1);
            r = tree.merge(new File("../resources/testsuite/EvolutionaryFuzzer/BranchTest/openssl2"));
            assertTrue("Failure: After merging the same File twice, no new Branches should be found, we found:"+r.getNewBranches(),r.getNewBranches() == 0);
            assertTrue("Failure: After merging the same File twice, no new Vertices should be found, we found:"+r.getNewBranches(),r.getNewVertices() == 0);
        }
        catch (IOException E)
        {
            e = E;
        }
        assertNull("Failure: The Test should not Throw an Exception. Might indicate that it could not find the Testfiles. ",e);
    }


}
