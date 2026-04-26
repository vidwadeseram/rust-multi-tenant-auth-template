use lettre::{message::Mailbox, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[derive(Clone)]
pub struct Mailer {
    client: AsyncSmtpTransport<Tokio1Executor>,
    sender: String,
}

impl Mailer {
    pub fn new(host: &str, port: u16, sender: &str) -> Self {
        let client = if port == 1025 {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                .port(port)
                .build()
        } else {
            match AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host) {
                Ok(transport) => transport.port(port).build(),
                Err(e) => {
                    tracing::error!(error = %e, "failed to create SMTP transport");
                    AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
                        .port(port)
                        .build()
                }
            }
        };

        Self {
            client,
            sender: sender.to_string(),
        }
    }

    pub async fn send_email(&self, recipient: &str, subject: &str, body: &str) {
        let sender = match self.sender.parse() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "invalid sender address");
                return;
            }
        };
        let recipient = match recipient.parse() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "invalid recipient address");
                return;
            }
        };

        let message = match Message::builder()
            .from(Mailbox::new(None, sender))
            .to(Mailbox::new(None, recipient))
            .subject(subject)
            .body(body.to_string())
        {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "failed to build email message");
                return;
            }
        };

        if let Err(e) = self.client.send(message).await {
            tracing::warn!(error = %e, "failed to send email");
        }
    }
}
