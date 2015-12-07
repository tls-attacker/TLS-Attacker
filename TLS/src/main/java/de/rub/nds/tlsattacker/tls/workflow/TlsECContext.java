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
package de.rub.nds.tlsattacker.tls.workflow;

import de.rub.nds.tlsattacker.tls.constants.ECPointFormat;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TlsECContext {
    /**
     * EC public key parameters for EC handshakes
     */
    private ECPublicKeyParameters clientPublicKeyParameters;
    /**
     * EC private key parameters
     */
    private ECPrivateKeyParameters clientPrivateKeyParameters;
    /**
     * EC public key parameters of the server
     */
    private ECPublicKeyParameters serverPublicKeyParameters;
    /**
     * supported named curves
     */
    private NamedCurve[] namedCurves;
    /**
     * supported server point formats
     */
    private ECPointFormat[] serverPointFormats;
    /**
     * supported client point formats
     */
    private ECPointFormat[] clientPointFormats;

    public void setClientPublicKeyParameters(ECPublicKeyParameters ecPublicKeyParameters) {
	this.clientPublicKeyParameters = ecPublicKeyParameters;
    }

    public ECPublicKeyParameters getClientPublicKeyParameters() {
	return clientPublicKeyParameters;
    }

    public ECPrivateKeyParameters getClientPrivateKeyParameters() {
	return clientPrivateKeyParameters;
    }

    public void setClientPrivateKeyParameters(ECPrivateKeyParameters clientPrivateKeyParameters) {
	this.clientPrivateKeyParameters = clientPrivateKeyParameters;
    }

    public NamedCurve[] getNamedCurves() {
	return namedCurves;
    }

    public void setNamedCurves(NamedCurve[] namedCurves) {
	this.namedCurves = namedCurves;
    }

    public ECPointFormat[] getServerPointFormats() {
	return serverPointFormats;
    }

    public void setServerPointFormats(ECPointFormat[] serverPointFormats) {
	this.serverPointFormats = serverPointFormats;
    }

    public ECPointFormat[] getClientPointFormats() {
	return clientPointFormats;
    }

    public void setClientPointFormats(ECPointFormat[] clientPointFormats) {
	this.clientPointFormats = clientPointFormats;
    }

    public ECPublicKeyParameters getServerPublicKeyParameters() {
	return serverPublicKeyParameters;
    }

    public void setServerPublicKeyParameters(ECPublicKeyParameters serverPublicKeyParameters) {
	this.serverPublicKeyParameters = serverPublicKeyParameters;
    }

}
