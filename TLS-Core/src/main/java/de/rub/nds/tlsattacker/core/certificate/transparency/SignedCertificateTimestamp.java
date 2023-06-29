/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLog;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogList;
import de.rub.nds.tlsattacker.core.certificate.transparency.logs.CtLogListLoader;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import org.bouncycastle.asn1.x509.Certificate;

public class SignedCertificateTimestamp {

    // Context used to verify the signature
    private Certificate certificate;
    private Certificate issuerCertificate;
    private SignedCertificateTimestampEntryType logEntryType;

    // Content of the SCT itself
    private byte[] encodedTimestamp;
    private SignedCertificateTimestampVersion version;
    private byte[] logId;
    private long timestamp;
    private byte[] extensions;
    private SignedCertificateTimestampSignature signature;

    public SignedCertificateTimestampVersion getVersion() {
        return version;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    public void setIssuerCertificate(Certificate issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
    }

    public SignedCertificateTimestampEntryType getLogEntryType() {
        return logEntryType;
    }

    public void setLogEntryType(SignedCertificateTimestampEntryType logEntryType) {
        this.logEntryType = logEntryType;
    }

    public void setVersion(SignedCertificateTimestampVersion version) {
        this.version = version;
    }

    public byte[] getLogId() {
        return logId;
    }

    public void setLogId(byte[] logId) {
        this.logId = logId;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getExtensions() {
        return extensions;
    }

    public void setExtensions(byte[] extensions) {
        this.extensions = extensions;
    }

    public SignedCertificateTimestampSignature getSignature() {
        return signature;
    }

    public void setSignature(SignedCertificateTimestampSignature signature) {
        this.signature = signature;
    }

    public void setEncodedTimestamp(byte[] encodedTimestamp) {
        this.encodedTimestamp = encodedTimestamp;
    }

    public String toString() {

        CtLogList logList = CtLogListLoader.loadLogList();
        CtLog ctLog = logList.getCtLog(logId);

        StringBuilder sb = new StringBuilder();
        sb.append("Signed Certificate Timestamp:");

        sb.append("\n Version: ");
        if (version == SignedCertificateTimestampVersion.V1) {
            sb.append("v1 (0x0)");
        } else {
            sb.append("0x").append(Integer.toHexString(encodedTimestamp[0]));
        }

        sb.append("\n Log: ");
        if (ctLog != null) {
            sb.append(ctLog.getDescription());
        } else {
            sb.append("Unknown Log");
        }

        sb.append("\n Log ID: ");
        sb.append(ArrayConverter.bytesToHexString(this.logId).replaceAll("\\n", "\n    "));

        sb.append("\n Timestamp: ");
        DateTimeFormatter outputFormatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        sb.append(
                outputFormatter.format(
                        LocalDateTime.ofEpochSecond(timestamp / 1000L, 0, ZoneOffset.UTC)));

        sb.append("\n Extensions: ");
        if (extensions.length == 0) {
            sb.append("none");
        } else {
            sb.append(ArrayConverter.bytesToHexString(extensions).replaceAll("\\n", "\n    "));
        }

        sb.append((signature.toString(this, ctLog)));

        return sb.toString();
    }
}
