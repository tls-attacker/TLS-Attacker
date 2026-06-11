/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.config.adapter;

import de.rub.nds.x509attacker.config.X509CertificateConfig;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.adapters.XmlAdapter;
import java.util.ArrayList;
import java.util.List;

public class CertificateChainConfigAdapter
        extends XmlAdapter<
                CertificateChainConfigAdapter.CertificateChainList,
                List<List<X509CertificateConfig>>> {

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class CertificateChainList {

        @XmlElement(name = "certificateChain")
        List<CertificateChainEntry> chains = new ArrayList<>();
    }

    @XmlAccessorType(XmlAccessType.FIELD)
    public static class CertificateChainEntry {

        @XmlElement(name = "certificateConfig")
        List<X509CertificateConfig> certificateConfigs = new ArrayList<>();
    }

    @Override
    public List<List<X509CertificateConfig>> unmarshal(CertificateChainList chainList)
            throws Exception {
        if (chainList == null) {
            return null;
        }
        List<List<X509CertificateConfig>> result = new ArrayList<>();
        for (CertificateChainEntry entry : chainList.chains) {
            result.add(entry.certificateConfigs);
        }
        return result;
    }

    @Override
    public CertificateChainList marshal(List<List<X509CertificateConfig>> configChains)
            throws Exception {
        if (configChains == null) {
            return null;
        }
        CertificateChainList list = new CertificateChainList();
        for (List<X509CertificateConfig> chain : configChains) {
            CertificateChainEntry entry = new CertificateChainEntry();
            entry.certificateConfigs = chain;
            list.chains.add(entry);
        }
        return list;
    }
}
