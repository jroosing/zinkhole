//! What zinkhole's HTTP clients share: the one that loads the lists and a
//! replica's.

use url::Url;

/// The client could not be set up.
#[derive(Debug, thiserror::Error)]
#[error("cannot set up the HTTP client: {0}")]
pub struct ClientError(#[from] reqwest::Error);

/// A client builder with what both clients want: TLS as `tls` says, zinkhole
/// as the user agent, and no proxy taken from the environment.
pub(crate) fn builder(tls: rustls::ClientConfig) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(concat!("zinkhole/", env!("CARGO_PKG_VERSION")))
        .no_proxy()
}

/// `error` as text, with the whole chain of causes ("error sending request"
/// alone says little) and without reqwest's "for url (...)": the URL may
/// hold a token.
pub(crate) fn error_text(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// `url` for a log line or an error: without credentials, query or
/// fragment, which may hold tokens.
pub(crate) fn shown_url(url: &Url) -> String {
    let mut shown = url.clone();
    let _ = shown.set_username("");
    let _ = shown.set_password(None);
    shown.set_query(None);
    shown.set_fragment(None);
    shown.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shown_url_has_no_credentials_query_or_fragment() {
        let url = Url::parse("https://user:secret@lists.example/ads.txt?token=abc#x").unwrap();
        assert_eq!(shown_url(&url), "https://lists.example/ads.txt");
    }

    #[tokio::test]
    async fn an_error_names_its_cause_but_not_the_url() {
        // Nothing listens on port 1.
        let client = builder(crate::tls::client_config(rustls::RootCertStore::empty()))
            .build()
            .unwrap();
        let error = client
            .get("http://127.0.0.1:1/list.txt?token=SECRET")
            .send()
            .await
            .unwrap_err();
        let text = error_text(error);
        assert!(text.contains(": "), "the causes too: {text}");
        assert!(
            !text.contains("SECRET") && !text.contains("list.txt"),
            "{text}"
        );
    }
}
