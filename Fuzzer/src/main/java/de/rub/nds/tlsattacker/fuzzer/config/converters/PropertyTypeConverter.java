/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.fuzzer.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import java.util.Arrays;

/**
 * Converts a Property type string to a PropertyType (for command line
 * purposes).
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class PropertyTypeConverter implements IStringConverter<ModifiableVariableProperty.Type> {

    @Override
    public ModifiableVariableProperty.Type convert(String value) {

	try {
	    return ModifiableVariableProperty.Type.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a VariablePropertyType. "
		    + "Available values are: " + Arrays.toString(ModifiableVariableProperty.Type.values()));
	}
    }
}
