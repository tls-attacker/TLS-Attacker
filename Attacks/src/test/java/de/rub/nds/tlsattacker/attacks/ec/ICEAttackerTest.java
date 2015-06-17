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

import de.rub.nds.tlsattacker.attacks.ec.oracles.TestECOracle;
import de.rub.nds.tlsattacker.attacks.ec.oracles.TestECSunOracle;
import java.math.BigInteger;
import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class ICEAttackerTest {

    public ICEAttackerTest() {
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Ignore("Takes too long")
    @Test()
    public void testAttack() {
	TestECOracle oracle = new TestECOracle("secp256r1");
	ICEAttacker attacker = new ICEAttacker(oracle);
	attacker.attack();
	BigInteger result = attacker.getResult();

	System.out.println(result);
	System.out.println(oracle.getComputer().getSecret());

	assertEquals(oracle.getComputer().getSecret(), result);
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Ignore("Takes too long")
    @Test
    public void testSunAttack() {
	TestECSunOracle oracle = new TestECSunOracle("secp256r1");
	ICEAttacker attacker = new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4);
	attacker.attack();
	BigInteger result = attacker.getResult();

	System.out.println(result);
	System.out.println(oracle.getComputer().getSecret());

	assertEquals(oracle.getComputer().getSecret(), result);
    }

    // @Ignore("Just a probability computation for our paper")
    @Test
    public void computeProbability() {
	double probability = 0.98;
	int results = 53;
	double result = Math.pow(probability, results)
		+ (results * (1 - probability) * Math.pow(probability, results - 1))
		+ (190 * Math.pow(1 - probability, 2) * Math.pow(probability, results - 2))
		+ (1140 * Math.pow(1 - probability, 3) * Math.pow(probability, results - 3));
	System.out.println(result);
    }

}
