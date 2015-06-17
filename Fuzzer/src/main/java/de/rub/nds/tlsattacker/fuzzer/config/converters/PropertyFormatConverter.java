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
package de.rub.nds.tlsattacker.fuzzer.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import java.util.Arrays;

/**
 * Converts a Property Format string to a PropertyFormat (for command line
 * purposes).
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PropertyFormatConverter implements IStringConverter<ModifiableVariableProperty.Format> {

    @Override
    public ModifiableVariableProperty.Format convert(String value) {

	try {
	    return ModifiableVariableProperty.Format.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a VariablePropertyFormat. "
		    + "Available values are: " + Arrays.toString(ModifiableVariableProperty.Format.values()));
	}
    }
}
