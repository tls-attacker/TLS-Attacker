/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Interprets a string as a file path and reads the whole file as a single
 * string.
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
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
