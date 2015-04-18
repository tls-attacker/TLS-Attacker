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
package de.rub.nds.tlsattacker.modifiablevariable;

import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;

/**
 * The base abstract class for modifiable variables, including the getValue
 * function.
 * 
 * The class needs to be defined transient to allow propOrder definition in
 * subclasses, see:
 * http://blog.bdoughan.com/2011/06/ignoring-inheritance-with-xmltransient.html
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @param <E>
 */
@XmlRootElement
@XmlTransient
public abstract class ModifiableVariable<E> {

    protected E originalValue;

    private VariableModification<E> modification = null;

    /**
     *
     */
    private boolean createRandomModification;

    public ModifiableVariable() {

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

    protected abstract void createRandomModification();

    public void createRandomModificationAtRuntime() {
	createRandomModification = true;
    }
}
