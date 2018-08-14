/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.gost;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cryptopro.GostR3410KeyTransport;

public class TLSProxyKeyTransportBlob extends ASN1Object {

    private final GostR3410KeyTransport keyBlob;
    private final DEROctetString cert;

    private TLSProxyKeyTransportBlob(ASN1Sequence seq) {
        this.keyBlob = GostR3410KeyTransport.getInstance(seq.getObjectAt(0));
        this.cert = (DEROctetString) DEROctetString.getInstance(seq.getObjectAt(1));
    }

    public TLSProxyKeyTransportBlob(GostR3410KeyTransport keyBlob, DEROctetString cert) {
        this.keyBlob = keyBlob;
        this.cert = cert;
    }

    public static TLSProxyKeyTransportBlob getInstance(Object obj) {
        if (obj instanceof TLSProxyKeyTransportBlob) {
            return (TLSProxyKeyTransportBlob) obj;
        }

        if (obj != null) {
            return new TLSProxyKeyTransportBlob(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public GostR3410KeyTransport getKeyBlob() {
        return keyBlob;
    }

    public DEROctetString getCert() {
        return cert;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(keyBlob);
        v.add(cert);
        return new DERSequence(v);
    }
}
