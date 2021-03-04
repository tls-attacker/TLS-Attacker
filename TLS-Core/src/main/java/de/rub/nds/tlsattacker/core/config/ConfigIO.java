/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.tlsattacker.core.config.filter.ConfigDisplayFilter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXB;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import org.xml.sax.SAXException;

public class ConfigIO {

    public static void write(Config config, File f) {
        try {
            write(config, new FileOutputStream(f));
        } catch (FileNotFoundException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void write(Config config, OutputStream os) {
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();

        JAXB.marshal(config, tempStream);
        try {
            os.write(new String(tempStream.toByteArray()).getBytes());
        } catch (IOException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static void write(Config config, File f, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, f);
    }

    public static void write(Config config, OutputStream os, ConfigDisplayFilter filter) {
        Config filteredConfig = copy(config);
        filter.applyFilter(filteredConfig);
        write(filteredConfig, os);
    }

    public static Config read(File f) {
        Config config = JAXB.unmarshal(f, Config.class);
        return config;
    }

    public static Config read(InputStream stream) {
        Config config = JAXB.unmarshal(stream, Config.class);
        return config;
    }

    public static Config copy(Config config) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ConfigIO.write(config, byteArrayOutputStream);
        return ConfigIO.read(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    }

    private ConfigIO() {
    }
}
