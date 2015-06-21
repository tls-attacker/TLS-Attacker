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
 * Construct the 802.1x Start-Header with Version
 * https://standards.ieee.org/findstds/standard/802.1X-2010.html
 * @author Felix Lange <flx.lange@gmail.com>
 */

public class Start8021X extends EAPFrame {

    byte version;

    public Start8021X(byte version) {

	this.version = version;
	createFrame();

    }

    @Override
    public void createFrame() {

	frame = new byte[4];
	frame[0] = version; // Version
	frame[1] = 0x01; // Type:Start
	frame[2] = 0x00;
	frame[3] = 0x00; // Length

    }

}
