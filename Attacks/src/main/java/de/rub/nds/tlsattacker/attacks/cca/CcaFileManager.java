/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.attacks.cca;

import de.rub.nds.x509attacker.filesystem.BinaryFileReader;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CcaFileManager {

    private static Logger LOGGER = LogManager.getLogger();

    private static Map<String, CcaFileManager> references = new HashMap<>();

    private File fileDirectory;

    private final Map<String, byte[]> fileMap = new HashMap<>();

    private CcaFileManager(String fileDirectory) {
        this.init(fileDirectory);
    }

    public static CcaFileManager getReference(String fileDirectory) {
        if (references.get(fileDirectory) == null) {
            synchronized (CcaFileManager.class) {
                if (references.get(fileDirectory) == null) {
                    references.put(fileDirectory, new CcaFileManager(fileDirectory));
                }
            }
        }
        return references.get(fileDirectory);
    }

    public void init(String fileDirectory) {
        if (fileMap.isEmpty()) {
            this.fileDirectory = new File(fileDirectory);
            this.readAllFiles();
        }
    }

    private void readAllFiles() {
        File[] files = this.fileDirectory.listFiles();
        if (files != null) {
            for (File file : files) {
                this.readFile(file);
            }
        }
    }

    private void readFile(File file) {
        try {
            BinaryFileReader binaryFileReader = new BinaryFileReader(file.getAbsolutePath());
            byte[] xmlFileContent = binaryFileReader.read();
            this.addFile(file.getName(), xmlFileContent);
        } catch (IOException e) {
            LOGGER.error("Encountered IOException when reading xmlInputFile. " + e);
        }
    }

    private void addFile(String filename, byte[] content) {
        String sanitizedFilename = this.sanitizeFileName(filename);
        if (!this.fileMap.containsKey(sanitizedFilename)) {
            this.fileMap.put(sanitizedFilename, content);
        }
    }

    private String sanitizeFileName(String filename) {
        return filename.trim();
    }

    public byte[] getFileContent(String filename) {
        String sanitizedFilename = this.sanitizeFileName(filename);
        if (this.fileMap.containsKey(sanitizedFilename)) {
            return this.fileMap.get(sanitizedFilename);
        } else {
            LOGGER.error("XML file " + filename + " is not available in XmlFileManger!");
        }
        return null;
    }
}
