/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FileHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void deleteFolder(File folder) {
        File[] files = folder.listFiles();
        if (files != null) {
            for (File f : files) {
                if (f.isDirectory()) {
                    deleteFolder(f);
                } else {
                    f.delete();
                }
            }
        }
        folder.delete();
    }

    public static String getResourceAsString(Class currentClass, String resourceFilePath) {
        InputStream is;
        if (!resourceFilePath.startsWith("/")) {
            is = currentClass.getResourceAsStream("/" + resourceFilePath);
        } else {
            is = currentClass.getResourceAsStream(resourceFilePath);
        }
        String contents = null;
        try {
            contents = inputStreamToString(is);
        } catch (IOException ex) {
            LOGGER.error("Unable to load resource file " + resourceFilePath);
            return null;
        }
        return contents;
    }

    public static String inputStreamToString(InputStream is) throws IOException {
        BufferedInputStream bis = new BufferedInputStream(is);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int result = bis.read();
        while (result != -1) {
            bos.write((byte) result);
            result = bis.read();
        }
        return bos.toString(StandardCharsets.UTF_8.name());
    }

    private FileHelper() {
    }

}
