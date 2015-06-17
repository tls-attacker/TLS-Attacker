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
package de.rub.nds.tlsattacker.attacks.ec;

import de.rub.nds.tlsattacker.tls.crypto.ec.Point;
import java.math.BigInteger;

/**
 * 
 * @author juraj
 */
public class ICEPoint extends Point {

    private int order;

    public ICEPoint() {

    }

    public ICEPoint(int order, BigInteger x, BigInteger y) {
	super(x, y);
	this.order = order;
    }

    public int getOrder() {
	return order;
    }

    public void setOrder(int order) {
	this.order = order;
    }

    public String toString() {
	StringBuilder sb = new StringBuilder();
	sb.append("Point order: ").append(order).append("\nX: ").append(x).append("\nY: ").append(y);
	return sb.toString();
    }

}
