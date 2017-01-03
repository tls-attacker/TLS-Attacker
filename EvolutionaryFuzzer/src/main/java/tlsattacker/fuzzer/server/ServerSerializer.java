/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.server;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import javax.xml.bind.JAXBContext;

/**
 * A class which is used to serialize and deserialize Server objects
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerSerializer {

    /**
     * Context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    /**
     * Writes a TLSServer to a File in XML format
     * 
     * @param server
     *            Server to serialize
     * @param file
     *            File to write to
     * @throws FileNotFoundException
     *             Thrown if the File does not exist
     */
    public static void write(TLSServer server, File file) throws FileNotFoundException {
        XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(new FileOutputStream(file)));
        encoder.writeObject(server);
        encoder.close();
    }

    /**
     * Read a TLSServer from an XML file
     * 
     * @param file
     *            File to read from
     * @return Read ServerObject
     * @throws FileNotFoundException
     *             If the File does not exist
     */
    public static TLSServer read(File file) throws FileNotFoundException {
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(file)));
        TLSServer o = (TLSServer) decoder.readObject();
        decoder.close();
        return o;
    }

    private ServerSerializer() {
    }
}
