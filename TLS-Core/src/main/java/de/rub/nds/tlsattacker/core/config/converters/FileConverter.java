/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Interprets a string as a file path and reads the whole file as a single
 * string.
 */
public class FileConverter implements IStringConverter<String> {

    @Override
    public String convert(String value) {

        try {
            Path path = FileSystems.getDefault().getPath(value);
            return new String(Files.readAllBytes(path));
        } catch (IOException | IllegalArgumentException e) {
            throw new ParameterException("File " + value + " could not be opened and read: " + e.getLocalizedMessage());
        }
    }
}
