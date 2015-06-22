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
package de.rub.nds.tlsattacker.eap;

/**
 * Construct the 802.1x Header for encapsulated EAP
 * https://standards.ieee.org/findstds/standard/802.1X-2010.html
 * 
 * @author Felix Lange <flx.lange@gmail.com>
 */
public class Eap8021X extends EAPFrame {

    byte version;

    public Eap8021X(byte version) {

	this.version = version;
	createFrame();

    }

    @Override
    public final void createFrame() {

	frame = new byte[2];
	frame[0] = version;
	frame[1] = 0x00;

    }

}
