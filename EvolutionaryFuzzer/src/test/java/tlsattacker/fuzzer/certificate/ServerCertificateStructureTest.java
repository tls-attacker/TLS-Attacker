/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package tlsattacker.fuzzer.certificate;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXB;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author ic0ns
 */
public class ServerCertificateStructureTest {

    private ServerCertificateStructure struct;

    public ServerCertificateStructureTest() {
    }

    @Before
    public void setUp() {
        struct = new ServerCertificateStructure(new File("key"), new File("cert"));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getKeyFile method, of class ServerCertificateStructure.
     */
    @Test
    public void testGetKeyFile() {
        assertEquals(struct.getKeyFile(), new File("key"));
    }

    /**
     * Test of getCertificateFile method, of class ServerCertificateStructure.
     */
    @Test
    public void testGetCertificateFile() {
        assertEquals(struct.getCertificateFile(), new File("cert"));
    }

    /**
     * Test of hashCode method, of class ClientCertificateStructure.
     */
    @Test
    public void testHashCode() {
        ServerCertificateStructure struct2 = new ServerCertificateStructure(new File("cert"), new File("key"));
        assertFalse(struct.hashCode() == struct2.hashCode());
        ServerCertificateStructure struct3 = new ServerCertificateStructure(new File("key"), new File("cert"));
        assertEquals(struct.hashCode(), struct3.hashCode());
    }

    /**
     * Test of equals method, of class ClientCertificateStructure.
     */
    @Test
    public void testEquals() {
        ServerCertificateStructure struct2 = new ServerCertificateStructure(new File("cert"), new File("key"));
        assertFalse(struct.equals(struct2));
        assertFalse(struct2.equals(struct));
        ServerCertificateStructure struct3 = new ServerCertificateStructure(new File("key"), new File("cert"));
        assertEquals(struct, struct3);
    }

    @Test
    public void testSerialisation() {
        ServerCertificateStructure struct2 = deserialize(serialize(struct));
        assertEquals(struct, struct2);
    }

    public String serialize(ServerCertificateStructure struct) {
        StringWriter writer = new StringWriter();
        JAXB.marshal(struct, writer);
        return writer.getBuffer().toString();
    }

    public ServerCertificateStructure deserialize(String input) {
        StringReader reader = new StringReader(input);
        return JAXB.unmarshal(reader, ServerCertificateStructure.class);
    }

}
