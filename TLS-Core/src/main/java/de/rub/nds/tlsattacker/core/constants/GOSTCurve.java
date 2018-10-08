/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public enum GOSTCurve {
    GostR3410_2001_CryptoPro_A(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A),
    GostR3410_2001_CryptoPro_B(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B),
    GostR3410_2001_CryptoPro_C(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C),
    GostR3410_2001_CryptoPro_XchA(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA),
    GostR3410_2001_CryptoPro_XchB(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB),
    Tc26_Gost_3410_12_256_paramSetA(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA),
    Tc26_Gost_3410_12_512_paramSetA(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA),
    Tc26_Gost_3410_12_512_paramSetB(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB),
    Tc26_Gost_3410_12_512_paramSetC(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC);

    private final ASN1ObjectIdentifier identifier;

    GOSTCurve(ASN1ObjectIdentifier identifier) {
        this.identifier = identifier;
    }

    public ASN1ObjectIdentifier getIdentifier() {
        return identifier;
    }

    public String getJavaName() {
        return name().replace('_', '-');
    }

    public boolean is512bit2012() {
        return name().contains("3410_12_512");
    }

    public static GOSTCurve fromNamedSpec(ECNamedCurveSpec spec) {
        return fromString(spec.getName());
    }

    public static GOSTCurve fromString(String name) {
        return GOSTCurve.valueOf(name.replace('-', '_'));
    }

}
