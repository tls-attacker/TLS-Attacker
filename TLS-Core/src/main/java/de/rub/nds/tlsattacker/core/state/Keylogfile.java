/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.state;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import jakarta.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Keylogfile {
    private static final Logger LOGGER = LogManager.getLogger();
    private String path;
    private boolean writeKeylog;
    private TlsContext tlsContext;

    public Keylogfile(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
        path = tlsContext.getConfig().getKeylogFilePath();
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

        this.writeKeylog = tlsContext.getConfig().isWriteKeylogFile();
    }

    public void writeKey(String identifier, byte[] key) {
        synchronized (Keylogfile.class) {
            if (!this.writeKeylog) {
                return;
            }

            try {
                File f = new File(this.path);
                assert f.getParentFile().exists() || f.getParentFile().mkdirs();
                assert f.exists() || f.createNewFile();
                try (FileWriter fw = new FileWriter(this.path, true)) {
                    fw.write(
                            identifier
                                    + " "
                                    + DatatypeConverter.printHexBinary(tlsContext.getClientRandom())
                                    + " "
                                    + DatatypeConverter.printHexBinary(key)
                                    + "\n");
                }

                FileWriter fw = new FileWriter(this.path, true);
                fw.write(
                        identifier
                                + " "
                                + DatatypeConverter.printHexBinary(tlsContext.getClientRandom())
                                + " "
                                + DatatypeConverter.printHexBinary(key)
                                + "\n");
                fw.close();
            } catch (Exception e) {
                LOGGER.error(e);
            }
        }
    }
}
