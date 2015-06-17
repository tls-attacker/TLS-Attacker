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
package de.rub.nds.tlsattacker.attacks.pkcs1;

import java.math.BigInteger;

/**
 * M interval as mentioned in the Bleichenbacher paper.
 * 
 * @author Christopher Meyer - christopher.meyer@rub.de
 * @version 0.1
 * 
 *          May 24, 2012
 */
public class Interval {

    public BigInteger lower;
    public BigInteger upper;

    public Interval(BigInteger a, BigInteger b) {
	this.lower = a;
	this.upper = b;
	if (a.compareTo(b) > 0) {
	    throw new RuntimeException("something went wrong, a cannot be greater than b");
	}
    }
}
