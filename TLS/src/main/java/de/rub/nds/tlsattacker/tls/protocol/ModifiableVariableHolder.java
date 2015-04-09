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
package de.rub.nds.tlsattacker.tls.protocol;

import de.rub.nds.tlsattacker.modifiablevariable.ModifiableVariable;
import de.rub.nds.tlsattacker.util.RandomHelper;
import de.rub.nds.tlsattacker.util.ReflectionHelper;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public abstract class ModifiableVariableHolder {

    /**
     * Lists all the modifiable variables declared in the class
     * 
     * @return
     */
    public List<Field> getAllModifiableVariableFields() {
	return ReflectionHelper.getFieldsUpTo(this.getClass(), null, ModifiableVariable.class);
    }

    /**
     * Returns a random field representing a modifiable variable from this class
     * 
     * @return
     */
    public Field getRandomModifiableVariableField() {
	List<Field> fields = getAllModifiableVariableFields();
	int randomField = RandomHelper.getRandom().nextInt(fields.size());
	return fields.get(randomField);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance
     * 
     * @return
     */
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
	List<ModifiableVariableHolder> holders = new LinkedList<>();
	holders.add(this);
	return holders;
    }

    /**
     * Returns a random modifiable variable holder
     * 
     * @return
     */
    public ModifiableVariableHolder getRandomModifiableVariableHolder() {
	List<ModifiableVariableHolder> holders = getAllModifiableVariableHolders();
	int randomHolder = RandomHelper.getRandom().nextInt(holders.size());
	return holders.get(randomHolder);
    }
}
