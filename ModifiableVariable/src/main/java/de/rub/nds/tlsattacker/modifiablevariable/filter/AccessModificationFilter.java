/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.modifiablevariable.filter;

import de.rub.nds.tlsattacker.modifiablevariable.ModificationFilter;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Filters modification executions for specific accesses, starting with 1.
 * 
 * For example, if one defines accessNumbers = {1,3} and executes four times
 * getValue() function on a modifiable variable, the modification is executed
 * only during the second and fourth getValue() method invocation.
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
public class AccessModificationFilter extends ModificationFilter {

    private int accessCounter;

    /**
     * accesses when the modification will be filtered (will not be executed)
     */
    private int[] accessNumbers;

    public AccessModificationFilter() {
	accessCounter = 1;
    }

    public AccessModificationFilter(final int[] accessNumbers) {
	accessCounter = 1;
	this.accessNumbers = accessNumbers;
    }

    @Override
    public boolean filterModification() {
	boolean filter = contains(accessNumbers, accessCounter);
	accessCounter++;
	return filter;
    }

    private boolean contains(int[] numbers, int number) {
	for (int i : numbers) {
	    if (i == number) {
		return true;
	    }
	}
	return false;
    }

    public int[] getAccessNumbers() {
	return accessNumbers;
    }

    public void setAccessNumbers(int[] accessNumbers) {
	this.accessNumbers = accessNumbers;
    }
}
