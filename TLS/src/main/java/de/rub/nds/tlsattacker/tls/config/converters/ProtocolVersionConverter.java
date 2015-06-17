/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import java.util.Arrays;

/**
 * Converts a protocol version string to a protocol Version enum (for command
 * line purposes).
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class ProtocolVersionConverter implements IStringConverter<ProtocolVersion> {

    @Override
    public ProtocolVersion convert(String value) {
	ProtocolVersion convertedValue = ProtocolVersion.fromString(value);

	if (convertedValue == null) {
	    throw new ParameterException("Value " + value + " cannot be converted to a protocol version. "
		    + "Available values are: " + Arrays.toString(ProtocolVersion.values()));
	}
	return convertedValue;
    }
}
