/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Juraj Somorovsky
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
package de.rub.nds.tlsattacker.util;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class Time {

    /**
     * Unix time means number of seconds since 1970, in GMT time zone.
     * Date.getTime() returns number of milliseconds since 1970 in GMT, thus we
     * convert it to seconds.
     * 
     * @return unix time
     */
    public static final long getUnixTime() {

	// long millis = new Date().getTime();
	long sec = System.currentTimeMillis() / 1000;

	return sec;
    }
}
