/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable;

import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerShiftLeftModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerShiftRightModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.biginteger.BigIntegerXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayDeleteModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayDuplicateModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayInsertModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayShuffleModification;
import de.rub.nds.tlsattacker.modifiablevariable.bytearray.ByteArrayXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.filter.AccessModificationFilter;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerShiftLeftModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerShiftRightModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.integer.IntegerXorModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteAddModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteExplicitValueModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteSubtractModification;
import de.rub.nds.tlsattacker.modifiablevariable.singlebyte.ByteXorModification;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlTransient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 * @author Christian Mainka - christian.mainka@rub.de
 * @param <E>
 */
@XmlRootElement
@XmlTransient
@XmlSeeAlso({ AccessModificationFilter.class, BigIntegerAddModification.class,
	BigIntegerExplicitValueModification.class, BigIntegerSubtractModification.class,
	BigIntegerXorModification.class, BigIntegerShiftLeftModification.class, BigIntegerShiftRightModification.class,
	IntegerAddModification.class, IntegerExplicitValueModification.class, IntegerSubtractModification.class,
	IntegerXorModification.class, IntegerShiftLeftModification.class, IntegerShiftRightModification.class,
	ByteArrayDeleteModification.class, ByteArrayExplicitValueModification.class, ByteArrayInsertModification.class,
	ByteArrayXorModification.class, ByteArrayDuplicateModification.class, ByteArrayShuffleModification.class,
	ByteAddModification.class, ByteExplicitValueModification.class, ByteSubtractModification.class,
	ByteXorModification.class })
public abstract class VariableModification<E> {

    private static final Logger LOGGER = LogManager.getLogger(VariableModification.class);

    /**
     * post modification for next modification executed on the given variable
     */
    private VariableModification<E> postModification = null;

    /**
     * In specific cases it is possible to filter out some modifications based
     * on given rules. ModificationFilter is responsible for validating if the
     * modification can be executed.
     */
    private ModificationFilter modificationFilter = null;

    /**
     * Get the value of postModification
     * 
     * @return the value of postModification
     */
    // http://stackoverflow.com/questions/5122296/jaxb-not-unmarshalling-xml-any-element-to-jaxbelement
    @XmlAnyElement(lax = true)
    final public VariableModification<E> getPostModification() {
	return postModification;
    }

    /**
     * Set the value of postModification
     * 
     * @param postModification
     *            new value of postModification
     */
    final public void setPostModification(VariableModification<E> postModification) {
	this.postModification = postModification;
    }

    public E modify(E input) {
	E modifiedValue = modifyImplementationHook(input);
	if (postModification != null) {
	    modifiedValue = postModification.modify(modifiedValue);
	}
	if ((modificationFilter == null) || (modificationFilter.filterModification() == false)) {
	    debug(modifiedValue);
	    return modifiedValue;
	} else {
	    return input;
	}
    }

    protected abstract E modifyImplementationHook(E input);

    /**
     * Debugging modified variables. Getting stack trace can be time consuming,
     * thus we use isDebugEnabled() function
     * 
     * @param value
     */
    protected void debug(E value) {
	if (LOGGER.isDebugEnabled()) {
	    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
	    int index = 0;
	    for (int i = 0; i < stack.length; i++) {
		if (stack[i].toString().contains("ModifiableVariable.getValue")) {
		    index = i + 1;
		}
	    }
	    String valueString;
	    if (value.getClass().getSimpleName().equals("byte[]")) {
		valueString = ArrayConverter.bytesToHexString((byte[]) value);
	    } else {
		valueString = value.toString();
	    }
	    LOGGER.debug("Using {} in function:\n  {}\n  New value: {}", this.getClass().getSimpleName(), stack[index],
		    valueString);
	}
    }

    public ModificationFilter getModificationFilter() {
	return modificationFilter;
    }

    public void setModificationFilter(ModificationFilter modificationFilter) {
	this.modificationFilter = modificationFilter;
    }
}
