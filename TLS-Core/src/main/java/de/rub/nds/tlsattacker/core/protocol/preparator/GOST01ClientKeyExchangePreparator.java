/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.crypto.ec.CustomECPoint;
import de.rub.nds.tlsattacker.core.protocol.message.GOSTClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.util.GOSTUtils;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;

public class GOST01ClientKeyExchangePreparator extends GOSTClientKeyExchangePreparator {

    public GOST01ClientKeyExchangePreparator(Chooser chooser, GOSTClientKeyExchangeMessage msg) {
        super(chooser, msg);
    }

    @Override
    protected String getServerCurve() {
        return chooser.getServerGost01Curve();
    }

    @Override
    protected String getKeyAgreementAlgorithm() {
        return "ECGOST3410";
    }

    @Override
    protected String getKeyPairGeneratorAlgorithm() {
        return getKeyAgreementAlgorithm();
    }

    @Override
    protected ASN1ObjectIdentifier getEncryptionParameters() {
        return CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet;
    }

    @Override
    protected boolean areParamSpecsEqual() {
        return chooser.getSelectedCipherSuite().usesGOSTR3411()
                && getServerCurve().equals(chooser.getClientGost01Curve());
    }

    @Override
    protected PrivateKey generatePrivateKey(BigInteger s) {
        return GOSTUtils.generate01PrivateKey(getServerCurve(), s);
    }

    @Override
    protected PublicKey generatePublicKey(CustomECPoint point) {
        return GOSTUtils.generate01PublicKey(getServerCurve(), point);
    }

    @Override
    protected BigInteger getClientPrivateKey() {
        return chooser.getClientGost01PrivateKey();
    }

    @Override
    protected CustomECPoint getClientPublicKey() {
        return chooser.getClientGost01PublicKey();
    }

    @Override
    protected BigInteger getServerPrivateKey() {
        return chooser.getServerGost01PrivateKey();
    }

    @Override
    protected CustomECPoint getServerPublicKey() {
        return chooser.getServerGost01PublicKey();
    }

}
