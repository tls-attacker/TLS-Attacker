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
import javax.xml.bind.JAXB;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
class TlsConfigIO {
    public static void write(TlsConfig config, File f) {
        JAXB.marshal(config, f);
    }

    public static TlsConfig read(File f) {
        TlsConfig config = JAXB.unmarshal(f, TlsConfig.class);
        return config;
    }

    public static TlsConfig read(InputStream stream) {
        TlsConfig config = JAXB.unmarshal(stream, TlsConfig.class);
        return config;
    }

    private TlsConfigIO() {
    }
}
