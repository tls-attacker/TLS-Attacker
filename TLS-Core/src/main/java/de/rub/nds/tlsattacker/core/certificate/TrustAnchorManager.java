/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate;

import de.rub.nds.tlsattacker.util.ComparableByteArray;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TrustAnchorManager {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<TrustPlatform> trustPlatformList;

    private HashMap<ComparableByteArray, TrustAnchor> trustAnchors;

    private Set<TrustAnchor> trustAnchorSet;

    public TrustAnchorManager() {
        this.trustPlatformList = new LinkedList<>();
        this.trustAnchors = new HashMap<>();
        this.trustAnchorSet = new HashSet<>();
    }

    public void addTrustPlaform(TrustPlatform platform) {
        trustPlatformList.add(platform);
        for (TrustAnchor anchor : platform.getTrustAnchors()) {
            if (!trustAnchors.containsKey(anchor.getSha256Fingerprint())) {
                trustAnchors.put(new ComparableByteArray(anchor.getSha256Fingerprint()), anchor);
            }
        }
        for (TrustAnchor entry : platform.getBlockedTrustAnchors()) {
            if (!trustAnchors.containsKey(entry.getSha256Fingerprint())) {
                trustAnchors.put(new ComparableByteArray(entry.getSha256Fingerprint()), entry);
            }
        }
    }

    public List<TrustPlatform> getTrustPlatformList() {
        return trustPlatformList;
    }

    public boolean isTrustAnchor(X509Certificate certificate) {
        if (trustAnchors.containsKey(new ComparableByteArray(certificate.getSha256Fingerprint()))) {
            LOGGER.debug("Found a trustAnchor for certificate");
            return true;
        } else {
            return false;
        }
    }

    public Set<TrustAnchor> getTrustAnchorSet() {
        return trustAnchorSet;
    }
}
