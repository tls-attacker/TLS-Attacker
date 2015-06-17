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
package de.rub.nds.tlsattacker.tls.crypto.ec;

import java.math.BigInteger;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class CurveFactory {

    private CurveFactory() {

    }

    public static Curve getNamedCurve(String namedCurve) {
	BigInteger p, a, b;
	int bits;
	String namedCurveLow = namedCurve.toLowerCase();

	switch (namedCurveLow) {
	    case "secp192r1":
		p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
		a = new BigInteger("6277101735386680763835789423207666416083908700390324961276");
		b = new BigInteger("2455155546008943817740293915197451784769108058161191238065");
		bits = 192;
		break;

	    case "secp256r1":
		p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		a = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948");
		b = new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291");
		bits = 256;
		break;
	    default:
		throw new UnsupportedOperationException("The provided curve " + namedCurve + " not supported yet");
	}
	return new Curve(namedCurveLow, p, a, b, bits);
    }

}
