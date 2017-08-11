/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDHPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.interfaces.DHPrivateKey;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class KeyGenerator {

    public static RSAPrivateKey getRSAPrivateKey(Chooser chooser) {
        if (chooser.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
            return new CustomRSAPrivateKey(chooser.getRsaModulus(), chooser.getConfig().getDefaultClientRSAPrivateKey());
        } else {
            return new CustomRSAPrivateKey(chooser.getRsaModulus(), chooser.getConfig().getDefaultServerRSAPrivateKey());
        }
    }

    public static ECPrivateKey getECPrivateKey(Chooser chooser) {
        if (chooser.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
            return new CustomECPrivateKey(chooser.getClientEcPrivateKey(), chooser.getSelectedCurve());
        } else {
            return new CustomECPrivateKey(chooser.getServerEcPrivateKey(), chooser.getSelectedCurve());
        }
    }

    public static ECPrivateKey getTokenBindingECPrivateKey(Chooser chooser) {
        return new CustomECPrivateKey(chooser.getConfig().getDefaultTokenBindingEcPrivateKey(), NamedCurve.SECP256R1);
    }

    public static DHPrivateKey getDHPrivateKey(Chooser chooser) {
        if (chooser.getConfig().getConnectionEndType() == ConnectionEndType.CLIENT) {
            return new CustomDHPrivateKey(chooser.getDhClientPrivateKey(), chooser.getDhModulus(),
                    chooser.getDhGenerator());
        } else {
            return new CustomDHPrivateKey(chooser.getDhServerPrivateKey(), chooser.getDhModulus(),
                    chooser.getDhGenerator());
        }
    }

    public static DSAPrivateKey getDSAPrivateKey(Chooser chooser) {
        return null;
    }
}
