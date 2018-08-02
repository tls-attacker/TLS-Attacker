/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDHPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomDSAPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomRSAPrivateKey;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.interfaces.DHPrivateKey;

public class KeyGenerator {

    public static RSAPrivateKey getRSAPrivateKey(Chooser chooser) {
        BigInteger modulus;
        BigInteger key;
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            modulus = chooser.getClientRsaModulus();
            key = chooser.getClientRSAPrivateKey();
        } else {
            modulus = chooser.getServerRsaModulus();
            key = chooser.getServerRSAPrivateKey();
        }
        return new CustomRSAPrivateKey(modulus, key);
    }

    public static ECPrivateKey getECPrivateKey(Chooser chooser) {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            return new CustomECPrivateKey(chooser.getClientEcPrivateKey(), chooser.getConfig()
                    .getDefaultEcCertificateCurve());
        } else {
            return new CustomECPrivateKey(chooser.getServerEcPrivateKey(), chooser.getConfig()
                    .getDefaultEcCertificateCurve());
        }
    }

    public static ECPrivateKey getTokenBindingECPrivateKey(Chooser chooser) {
        return new CustomECPrivateKey(chooser.getConfig().getDefaultTokenBindingEcPrivateKey(), NamedGroup.SECP256R1);
    }

    public static DHPrivateKey getDHPrivateKey(Chooser chooser) {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            return new CustomDHPrivateKey(chooser.getDhClientPrivateKey(), chooser.getClientDhModulus(),
                    chooser.getClientDhGenerator());
        } else {
            return new CustomDHPrivateKey(chooser.getDhServerPrivateKey(), chooser.getServerDhModulus(),
                    chooser.getServerDhGenerator());
        }
    }

    public static DSAPrivateKey getDSAPrivateKey(Chooser chooser) {
        if (chooser.getConnectionEndType() == ConnectionEndType.CLIENT) {
            // TODO
            throw new UnsupportedOperationException("DSA currently only supported for Servers");
        } else {
            return new CustomDSAPrivateKey(chooser.getConfig().getDefaultServerDsaPrivateKey(), chooser.getDsaPrimeP(),
                    chooser.getDsaPrimeQ(), chooser.getDsaGenerator());
        }
    }
}
