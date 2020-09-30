/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.certificate.transparency;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

public class SignedCertificateTimestamp {

    private byte[] encodedTimestamp;
    private SignedCertificateTimestampVersion version;
    private byte[] logId;
    private long timestamp;
    private byte[] extensions;
    private byte[] signature;

    public SignedCertificateTimestampVersion getVersion() {
        return version;
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

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public void setEncodedTimestamp(byte[] encodedTimestamp) {
        this.encodedTimestamp = encodedTimestamp;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Signed Certificate Timestamp:");

        sb.append("\n Version: ");
        if (version == SignedCertificateTimestampVersion.V1) {
            sb.append("v1 (0x0)");
        } else {
            sb.append(Integer.toHexString(encodedTimestamp[0]));
        }

        sb.append("\n Log ID: ");
        sb.append(ArrayConverter.bytesToHexString(this.logId).replaceAll("\\n", "\n    "));

        sb.append("\n Timestamp: ");
        DateTimeFormatter outputFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
        sb.append(outputFormatter.format(LocalDateTime.ofEpochSecond(timestamp / 1000L, 0, ZoneOffset.UTC)));

        sb.append("\n Extensions: ");
        if (extensions.length == 0) {
            sb.append("none");
        } else {
            sb.append(ArrayConverter.bytesToHexString(extensions).replaceAll("\\n", "\n    "));
        }

        sb.append("\n Signature: ");
        sb.append(ArrayConverter.bytesToHexString(signature).replaceAll("\\n", "\n    "));

        return sb.toString();
    }
}
