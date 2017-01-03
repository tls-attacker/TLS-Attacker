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
 * @author Robert Merget - robert.merget@rub.de
 */
public class ClientCertificateStructureTest {

    private ClientCertificateStructure struct;

    public ClientCertificateStructureTest() {
    }

    @Before
    public void setUp() {
        struct = new ClientCertificateStructure("password", "alias", new File("."));
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getPassword method, of class ClientCertificateStructure.
     */
    @Test
    public void testGetPassword() {
        assertEquals(struct.getPassword(), "password");
    }

    /**
     * Test of getAlias method, of class ClientCertificateStructure.
     */
    @Test
    public void testGetAlias() {
        assertEquals(struct.getAlias(), "alias");
    }

    /**
     * Test of getJKSfile method, of class ClientCertificateStructure.
     */
    @Test
    public void testGetJKSfile() {
        assertEquals(struct.getJKSfile(), new File("."));
    }

    /**
     * Test of hashCode method, of class ClientCertificateStructure.
     */
    @Test
    public void testHashCode() {
        ClientCertificateStructure struct2 = new ClientCertificateStructure("password", "alias", new File(
                "not_the_same_file"));
        assertFalse(struct.hashCode() == struct2.hashCode());
        ClientCertificateStructure struct3 = new ClientCertificateStructure("password", "alias", new File("."));
        assertEquals(struct.hashCode(), struct3.hashCode());
    }

    /**
     * Test of equals method, of class ClientCertificateStructure.
     */
    @Test
    public void testEquals() {
        ClientCertificateStructure struct2 = new ClientCertificateStructure("password", "alias", new File(
                "not_the_same_file"));
        assertFalse(struct.equals(struct2));
        assertFalse(struct2.equals(struct));
        ClientCertificateStructure struct3 = new ClientCertificateStructure("password", "alias", new File("."));
        assertEquals(struct, struct3);
    }

    @Test
    public void testSerialisation() {
        ClientCertificateStructure struct2 = deserialize(serialize(struct));
        assertEquals(struct, struct2);
    }

    public String serialize(ClientCertificateStructure struct) {
        StringWriter writer = new StringWriter();
        JAXB.marshal(struct, writer);
        return writer.getBuffer().toString();
    }

    public ClientCertificateStructure deserialize(String input) {
        StringReader reader = new StringReader(input);
        return JAXB.unmarshal(reader, ClientCertificateStructure.class);
    }
}
