package de.rub.nds.tlsattacker.core.smtp.reply.specific.multiline.data;

public class SmtpVRFYData {
    String username;
    String mailbox;

    public SmtpVRFYData(String username, String mailbox) {
        this.username = username;
        this.mailbox = mailbox;
    }

    public SmtpVRFYData(String mailbox) {
        this.mailbox = mailbox;
    }

    public String getUsername() {
        return username;
    }

    public String getMailbox() {
        return mailbox;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        if (this.username != null) {
            sb.append(this.username);
            sb.append(' ');
        }
        sb.append(this.mailbox);

        return sb.toString();
    }
}
