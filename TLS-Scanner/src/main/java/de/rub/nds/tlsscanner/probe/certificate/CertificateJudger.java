/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsscanner.flaw.ConfigurationFlaw;
import de.rub.nds.tlsscanner.flaw.FlawLevel;
import de.rub.nds.tlsscanner.report.ResultValue;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class CertificateJudger {

    public List<ConfigurationFlaw> getFlaws(X509CertificateObject certificate, String domainName) {
        List<ConfigurationFlaw> configurationFlaws = new LinkedList<>();
        if(certificate == null)
        {
            configurationFlaws.add(new ConfigurationFlaw("Could not retrieve Certificate", FlawLevel.FATAL, domainName, ""));
            return configurationFlaws;
        }
        if (isCertificateExpired(certificate)) {
            configurationFlaws
                    .add(new ConfigurationFlaw(
                            "Zertifikat ausgelaufen",
                            FlawLevel.FATAL,
                            "Das Zertifikat ist ausgelaufen. Zertifikate haben nur eine begrenzte gültigkeit und müssen von Zeit zu Zeit erneuert werden. Ein abgelaufenes Zertifikat schwächt eine TLS Verbindung enorm.",
                            "Beantragen sie ein neues Zertifikat!"));
        }
        if (isCertificateValidYet(certificate)) {
            configurationFlaws
                    .add(new ConfigurationFlaw(
                            "Zertifikat noch nicht gültig",
                            FlawLevel.FATAL,
                            "Das Zertifikat ist noch nicht gültig. Zertifikate haben ein gültigkeits Zeitraum und das konfigurierte Zertifikat ist noch nicht gültig. Ein noch nicht gültiges Zertifikat schwächt eine TLS Verbindung enorm.",
                            "Beantrage sie ein Zertifikat welches schon gültig ist!"));
        }
        if (isRevoked(certificate)) {
            configurationFlaws.add(new ConfigurationFlaw("Zertifikat zurückgerufen", FlawLevel.FATAL,
                    "Das eingesetzte Zertifikat wurde zurück gerufen und darf nicht mehr eingesetzt werden.",
                    "Beantrage sie ein neues Zertifikat."));
        }
        if (usesMD2signature(certificate)) {
            configurationFlaws
                    .add(new ConfigurationFlaw(
                            "MD2 Signatur",
                            FlawLevel.FATAL,
                            "Das eingesetzte Zertifikat benutzt den veralteten MD2 Algorithmus in seiner Signatur. Dies erlaubt das fälschen von Zertifikaten und schwächt die TLS-Verbindung erheblich.",
                            "Beantrage sie ein neues Zertifikat mit einem sicheren Hash-Algorithmus wie z.B. SHA-256"));
        }
        if (usesMD5signature(certificate)) {
            configurationFlaws
                    .add(new ConfigurationFlaw(
                            "MD5 Signatur",
                            FlawLevel.FATAL,
                            "Das eingesetzte Zertifikat benutzt den veralteten MD5 Algorithmus in seiner Signatur. Dies erlaubt das fälschen von Zertifikaten und schwächt die TLS-Verbindung erheblich.",
                            "Beantrage sie ein neues Zertifikat mit einem sicheren Hash-Algorithmus wie z.B. SHA-256"));
        }
        if (domainNameDoesNotMatch(certificate, domainName)) {
            configurationFlaws.add(new ConfigurationFlaw("Domain nicht zulässig", FlawLevel.FATAL,
                    "Das eingesetzte Zertifikat ist für die gescannte Domain nicht gültig.",
                    "Beantrage sie ein neues Zertifikat welches ebenfalls für die Domain " + domainName
                            + " gültig ist."));
        }
        if (isNotTrusted(certificate)) {
            configurationFlaws.add(new ConfigurationFlaw("Zertifikat nicht vertrauenswürdig", FlawLevel.FATAL,
                    "Dem Eingesetzten Zertifikat wird nicht vertraut",
                    "Beantrage sie ein neues Zertifikat welchem Vertraut werden kann."));
        }
        if (isSelfSigned(certificate)) {
            configurationFlaws
                    .add(new ConfigurationFlaw(
                            "Zertifikat ist selbst signiert",
                            FlawLevel.FATAL,
                            "Das eingesetzte Zertifikat legitimiert sich selbst. Besucher ihrer Seite können die Validität dieses Zertifikats nicht überprüfen.",
                            "Beantragen sie ein Zertifikat bei einer vertrauenswürdigen Zertifizierungsstelle."));
        }
        if (isWeakKey(certificate)) {
            configurationFlaws.add(getWeakKeyFlaw(certificate));
        }
        return configurationFlaws;
    }

    public boolean isWeakKey(X509CertificateObject certificate) {
        // TODO
        return false;
    }

    public ConfigurationFlaw getWeakKeyFlaw(X509CertificateObject certificate) {
        // TODO
        return new ConfigurationFlaw(null, FlawLevel.FATAL, null, null);
    }

    public boolean isCertificateExpired(X509CertificateObject certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException E) {
            return true;
        } catch (CertificateNotYetValidException E) {
            return false;
        }
        return false;
    }

    public boolean isCertificateValidYet(X509CertificateObject certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateNotYetValidException E) {
            return true;
        } catch (CertificateExpiredException E) {
            return false;
        }
        return false;
    }

    public boolean isRevoked(X509CertificateObject certificate) {
        // TODO
        return false;
    }

    public boolean usesMD2signature(X509CertificateObject certificate) {
        // TODO
        // if(certificate.)
        return false;
    }

    public boolean usesMD5signature(X509CertificateObject certificate) {
        // TODO
        return false;
    }

    public boolean domainNameDoesNotMatch(X509CertificateObject certificate, String domainName) {
        // TODO
        return false;
    }

    private boolean isNotTrusted(X509CertificateObject certificate) {
        // TODO
        return false;
    }

    private boolean isSelfSigned(X509CertificateObject certificate) {
        return false;
        //TODO
        //throw new UnsupportedOperationException("Not supported yet."); // To
                                                                       // change
                                                                       // body
                                                                       // of
                                                                       // generated
                                                                       // methods,
                                                                       // choose
                                                                       // Tools
                                                                       // |
                                                                       // Templates.
    }

    public List<ResultValue> getResults(X509CertificateObject serverCert, String serverHost) {
        return new LinkedList<>();
        // TODO
    }

}
