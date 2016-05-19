/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.util;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import java.lang.reflect.Field;

/**
 * Represents an object with its modifiable variable field.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ModifiableVariableField {

    private Object object;

    private Field field;

    public ModifiableVariableField() {

    }

    public ModifiableVariableField(Object o, Field f) {
	this.object = o;
	this.field = f;
    }

    public Object getObject() {
	return object;
    }

    public void setObject(Object object) {
	this.object = object;
    }

    public Field getField() {
	return field;
    }

    public void setField(Field field) {
	this.field = field;
    }

    public ModifiableVariable getModifiableVariable() throws IllegalArgumentException, IllegalAccessException {
	field.setAccessible(true);
	return (ModifiableVariable) field.get(object);
    }

}
