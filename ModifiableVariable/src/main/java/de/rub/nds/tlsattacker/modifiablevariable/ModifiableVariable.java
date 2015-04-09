/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayInsertModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteModificationFactory;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteXorModification;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author juraj
 * @param <E>
 */
@XmlRootElement
@XmlType(propOrder = { "variableClass", "originalValue", "modification" })
@XmlSeeAlso({ BigIntegerAddModification.class, BigIntegerExplicitValueModification.class,
	BigIntegerSubtractModification.class, BigIntegerXorModification.class, IntegerAddModification.class,
	IntegerExplicitValueModification.class, IntegerSubtractModification.class, IntegerXorModification.class,
	ByteArrayDeleteModification.class, ByteArrayExplicitValueModification.class, ByteArrayInsertModification.class,
	ByteArrayXorModification.class, ByteAddModification.class, ByteExplicitValueModification.class,
	ByteSubtractModification.class, ByteXorModification.class })
public class ModifiableVariable<E> implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger(ModifiableVariable.class);

    private E originalValue;

    private VariableModification<E> modification = null;

    /**
     * A hack to find out which variable we are dealing with (I was unable to
     * achieve this with a reflection).
     */
    private Class variableClass;

    /**
     *
     */
    private boolean createRandomModification;

    public ModifiableVariable() {

    }

    public ModifiableVariable(Class clazz) {
	this.variableClass = clazz;
    }

    public E getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(E originalValue) {
	this.originalValue = originalValue;
    }

    public void setModification(VariableModification<E> modification) {
	this.modification = modification;
    }

    @XmlAnyElement(lax = true)
    public VariableModification<E> getModification() {
	return modification;
    }

    public E getValue() {
	if (createRandomModification) {
	    createRandomModification();
	    createRandomModification = false;
	}

	if (modification != null) {
	    return modification.modify(originalValue);
	}
	return originalValue;
    }

    public Class getVariableClass() {
	return variableClass;
    }

    public void setVariableClass(Class variableClass) {
	this.variableClass = variableClass;
    }

    private void createRandomModification() {
	VariableModification vm;

	switch (variableClass.getSimpleName()) {
	    case "Integer":
		vm = IntegerModificationFactory.createRandomModification();
		setModification(vm);
		break;
	    case "BigInteger":
		vm = BigIntegerModificationFactory.createRandomModification();
		setModification(vm);
		break;
	    case "byte[]":
		vm = ByteArrayModificationFactory.createRandomModification((byte[]) originalValue);
		setModification(vm);
		break;
	    case "Byte":
		vm = ByteModificationFactory.createRandomModification();
		setModification(vm);
		break;
	    default:
		throw new RuntimeException("no variable class found");
	}
    }

    public void createRandomModificationAtRuntime() {
	createRandomModification = true;
    }

    // public static final void
    // initializeSafelyBigInteger(ModifiableVariable<BigInteger>
    // modifiableVariable) {
    // if (modifiableVariable == null) {
    // modifiableVariable = new ModifiableVariable<>();
    // }
    // }
    //
    // public static final void
    // initializeSafelyInteger(ModifiableVariable<Integer> modifiableVariable) {
    // if (modifiableVariable == null) {
    // modifiableVariable = new ModifiableVariable<>();
    // }
    // }
    //
    // public static final void
    // initializeSafelyByteArray(ModifiableVariable<byte[]> modifiableVariable)
    // {
    // if (modifiableVariable == null) {
    // modifiableVariable = new ModifiableVariable<>();
    // }
    // }
}
