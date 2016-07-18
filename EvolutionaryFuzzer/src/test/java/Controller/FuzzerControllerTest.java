/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Controller;

import Config.EvolutionaryFuzzerConfig;
import Controller.FuzzerController;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class FuzzerControllerTest {

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }
    /*
     * This Test is probably not vialble TODO
     * 
     * @Test public void testStartStopFuzzer() { EvolutionaryFuzzerConfig config
     * = new EvolutionaryFuzzerConfig(); FuzzerController con = new
     * FuzzerController(config); assertFalse(con.isRunning());
     * con.startFuzzer(); assertTrue(con.isRunning()); con.stopFuzzer();
     * assertFalse(con.isRunning());
     * 
     * }
     */
    
    public FuzzerControllerTest() {
    }


}
