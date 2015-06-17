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

public final class EapConstants {

    /** Broadcast address of EAP packet */
    public static final byte[] BROADCAST_ADDRESS = { (byte) 0x01, (byte) 0x80, (byte) 0xc2, (byte) 0x00, (byte) 0x00,
	    (byte) 0x03 };

    /** EAP packet frame type */
    public static final byte[] ETHERTYPE_EAP = { (byte) 0x88, (byte) 0x8e };

}
