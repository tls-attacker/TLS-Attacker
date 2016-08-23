/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package Helper;

import Config.Mutator.SimpleMutatorConfig;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class XMLSerializer {
    /**
     * 
     * @param f
     * @param file
     * @throws Exception
     */
    public static void write(Object f, File file) throws FileNotFoundException, IOException {
	if (!file.exists()) {
	    file.createNewFile();
	}
	XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(new FileOutputStream(file)));
	encoder.writeObject(f);
	encoder.close();
    }

    /**
     * 
     * @param file
     * @return
     * @throws Exception
     */
    public static Object read(File file) throws FileNotFoundException {
	XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(file)));
	Object o = decoder.readObject();
	decoder.close();
	return o;
    }
}
