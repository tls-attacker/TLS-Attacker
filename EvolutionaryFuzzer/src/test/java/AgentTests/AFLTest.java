package AgentTests;

import java.io.File;
import java.util.logging.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import static org.junit.Assert.*;

public class AFLTest {

    /**
     *
     */
    public AFLTest() {
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

    /**
     *
     */
    public void testIsCompiled() {
	File f = new File("AFL/afl-as");
	assertTrue(f.exists());
	f = new File("AFL/afl-showmap");
	assertTrue(f.exists());

    }

    private static final Logger LOG = Logger.getLogger(AFLTest.class.getName());
}
