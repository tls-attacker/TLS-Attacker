/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.state;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.xml.bind.DatatypeConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Keylogfile {
    private static final Logger LOGGER = LogManager.getLogger();
    private String path;
    private boolean writeKeylog;
    private TlsContext context;

    Keylogfile(TlsContext context) {
        this.context = context;
        path = context.getConfig().getKeylogFilePath();
        Path outputPath;
        if (path == null) {
            outputPath = Paths.get(System.getProperty("user.dir"), "keyfile.log");
        } else {
            outputPath = Paths.get(path);
            if (path.endsWith("/") || path.endsWith("\\")) {
                outputPath = Paths.get(path, "keyfile.log");
            }
        }

        outputPath = outputPath.toAbsolutePath();
        this.path = outputPath.toString();

        this.writeKeylog = context.getConfig().isWriteKeylogFile();
    }

    public void writeKey(String identifier, byte[] key) {
        synchronized (Keylogfile.class) {
            if (!this.writeKeylog) {
                return;
            }

            try {
                File f = new File(this.path);
                if (!f.exists()) {
                    f.getParentFile().mkdirs();
                    f.createNewFile();
                }

                FileWriter fw = new FileWriter(this.path, true);
                fw.write(identifier + " " + DatatypeConverter.printHexBinary(context.getClientRandom()) + " "
                    + DatatypeConverter.printHexBinary(key) + "\n");
                fw.close();
            } catch (Exception e) {
                LOGGER.error(e);
            }
        }
    }

}
