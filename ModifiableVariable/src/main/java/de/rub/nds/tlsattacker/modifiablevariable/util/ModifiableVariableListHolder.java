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
package de.rub.nds.tlsattacker.modifiablevariable.util;

import java.lang.reflect.Field;
import java.util.List;

/**
 * Represents a modifiable variable holder (an object containing at least one
 * ModifiableVariable field), containing a list of its ModifiableVariable fields
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ModifiableVariableListHolder {

    private Object object;

    private List<Field> fields;

    public ModifiableVariableListHolder() {

    }

    public ModifiableVariableListHolder(Object o, List<Field> f) {
	this.object = o;
	this.fields = f;
    }

    public Object getObject() {
	return object;
    }

    public void setObject(Object object) {
	this.object = object;
    }

    public List<Field> getFields() {
	return fields;
    }

    public void setFields(List<Field> fields) {
	this.fields = fields;
    }

}
