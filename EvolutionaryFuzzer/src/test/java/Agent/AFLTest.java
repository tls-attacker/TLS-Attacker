package Agent;

import java.io.File;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

public class AFLTest {
    private static final Logger LOG = Logger.getLogger(AFLTest.class.getName());

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
    public AFLTest() {
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
    public void testAflexists() {
	File f = new File("AFL/afl-as");
	assertTrue("Failure: Tool afl-as was not found", f.exists());
	f = new File("AFL/afl-showmap");
	assertTrue("Failure: Tool afl-showmap was not found", f.exists());

    }

}
