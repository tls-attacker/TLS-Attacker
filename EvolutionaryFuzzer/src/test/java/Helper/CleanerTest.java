/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Helper;

import Config.EvolutionaryFuzzerConfig;
import java.io.File;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class CleanerTest {

    public CleanerTest() {
    }

    /**
     * Test of cleanTraces method, of class Cleaner.
     */
    @Test
    public void testCleanTraces() {

	EvolutionaryFuzzerConfig evoConfig = new EvolutionaryFuzzerConfig();

	evoConfig.setOutputFolder("JUNIT/");
	File f = new File(evoConfig.getOutputFolder() + "traces/");
	f.mkdirs();
	Cleaner.cleanTraces(evoConfig);
    }

    /**
     * Test of cleanAll method, of class Cleaner.
     */
    @Test
    public void testCleanAll() {
	EvolutionaryFuzzerConfig evoConfig = new EvolutionaryFuzzerConfig();

	evoConfig.setOutputFolder("JUNIT/");
	File f = new File(evoConfig.getOutputFolder() + "traces/");
	f.mkdirs();
	f = new File(evoConfig.getOutputFolder() + "faulty/");
	f.mkdirs();
	f = new File(evoConfig.getOutputFolder() + "good/");
	f.mkdirs();
	Cleaner.cleanAll(evoConfig);
    }

}
