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
package de.rub.nds.tlsattacker.modifiablevariable.integer;

import de.rub.nds.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@XmlRootElement
@XmlType(propOrder = { "summand", "modificationFilter", "postModification" })
public class IntegerAddModification extends VariableModification<Integer> {

    private Integer summand;

    public IntegerAddModification() {

    }

    public IntegerAddModification(Integer bi) {
	this.summand = bi;
    }

    @Override
    protected Integer modifyImplementationHook(final Integer input) {
	return input + summand;
    }

    public Integer getSummand() {
	return summand;
    }

    public void setSummand(Integer summand) {
	this.summand = summand;
    }
}
