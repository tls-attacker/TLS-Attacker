/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.WorkflowTrace;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Robert Merget <robert.merget@rub.de>
 */
public final class ServerSerializer
{

    /**
     * context initialization is expensive, we need to do that only once
     */
    private static JAXBContext context;

    private ServerSerializer()
    {

    }

    public static void write(TLSServer f, File file) throws Exception
    {
        XMLEncoder encoder
                = new XMLEncoder(
                        new BufferedOutputStream(
                                new FileOutputStream(file)));
        encoder.writeObject(f);
        encoder.close();
    }

    public static TLSServer read(File file) throws Exception
    {
        XMLDecoder decoder
                = new XMLDecoder(new BufferedInputStream(
                                new FileInputStream(file)));
        TLSServer o = (TLSServer) decoder.readObject();
        decoder.close();
        return o;
    }
}
