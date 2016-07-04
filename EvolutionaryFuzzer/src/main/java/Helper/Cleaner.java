/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Helper;

import java.io.File;
import tls.rub.evolutionaryfuzzer.EvolutionaryFuzzerConfig;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Cleaner {
    
    public static void cleanTraces(EvolutionaryFuzzerConfig evoConfig) {
        File f = new File(evoConfig.getOutputFolder() + "traces/");
        delete(f);
                
    }
    public static void cleanAll(EvolutionaryFuzzerConfig evoConfig) {
        File f = new File(evoConfig.getOutputFolder() + "traces/");
        delete(f);
        f = new File(evoConfig.getOutputFolder() + "faulty/");
        delete(f);
        f = new File(evoConfig.getOutputFolder() + "good/");
        delete(f);
    }
    

    /**
     * Deletes all Files in a Folder which do not start with a "."
     * @param f 
     */
    private static void delete(File f) {
        if(!f.exists() || !f.isDirectory())
        {
            throw new IllegalArgumentException("File is not a Folder or does not exist!");
        }
        for (File file : f.listFiles()) {
            if (file.getName().startsWith(".")) {
                continue;
            } else {
                file.delete();
            }
        }
    }
}
