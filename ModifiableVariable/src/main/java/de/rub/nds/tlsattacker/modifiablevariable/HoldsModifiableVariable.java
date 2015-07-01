/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation interface for modifiable variables holders.
 * 
 * Depth says how deep in the structure the ModifiableVariable is (for example,
 * if the holder is stored in a list, depth=3 is appropriate).
 * The depth parameter can be modified for performance reasons.
 *
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface HoldsModifiableVariable {

    int depth() default 4;

}
