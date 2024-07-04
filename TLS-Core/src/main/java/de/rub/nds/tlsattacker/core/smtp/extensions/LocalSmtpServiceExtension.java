package de.rub.nds.tlsattacker.core.smtp.extensions;

/**
 *    In addition, any EHLO keyword value starting with an upper or lower
 *    case "X" refers to a local SMTP service extension used exclusively
 *    through bilateral agreement.  Keywords beginning with "X" MUST NOT be
 *    used in a registered service extension.  Conversely, keyword values
 *    presented in the EHLO response that do not begin with "X" MUST
 *    correspond to a Standard, Standards-Track, or IESG-approved
 *    Experimental SMTP service extension registered with IANA.  A
 *    conforming server MUST NOT offer non-"X"-prefixed keyword values that
 *    are not described in a registered extension.
 */
public class LocalSmtpServiceExtension extends SmtpServiceExtension {
    public LocalSmtpServiceExtension(String ehloKeyword, String parameters) {
        super(ehloKeyword);
    }
}
