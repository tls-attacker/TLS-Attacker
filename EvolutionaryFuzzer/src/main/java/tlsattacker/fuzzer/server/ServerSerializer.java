package tlsattacker.fuzzer.server;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
/**
 * A class which is used to serialize and deserialize Server objects
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerSerializer {

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    private static final Logger LOG = Logger.getLogger(ServerSerializer.class.getName());

    /**
     * 
     * @param f
     * @param file
     * @throws Exception
     */
    public static void write(TLSServer f, File file) throws Exception {
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
    public static TLSServer read(File file) throws FileNotFoundException {
	XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(file)));
	TLSServer o = (TLSServer) decoder.readObject();
	decoder.close();
	return o;
    }

    private ServerSerializer() {
    }
}
