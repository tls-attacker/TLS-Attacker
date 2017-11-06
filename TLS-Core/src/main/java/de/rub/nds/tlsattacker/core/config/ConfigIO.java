/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXB;

/**
 *

 */
public class ConfigIO {
    public static void write(Config config, File f) {
        JAXB.marshal(config, f);
    }

    public static void write(Config config, OutputStream os) {
        JAXB.marshal(config, os);
    }

    public static Config read(File f) {
        Config config = JAXB.unmarshal(f, Config.class);
        return config;
    }

    public static Config read(InputStream stream) {
        Config config = JAXB.unmarshal(stream, Config.class);
        return config;
    }

    private ConfigIO() {
    }
}
