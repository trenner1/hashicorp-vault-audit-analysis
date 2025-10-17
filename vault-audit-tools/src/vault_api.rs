use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::env;
use std::fs;

/// Check if TLS verification should be skipped based on environment or flag
pub fn should_skip_verify(insecure_flag: bool) -> bool {
    if insecure_flag {
        return true;
    }
    
    // Check VAULT_SKIP_VERIFY environment variable
    env::var("VAULT_SKIP_VERIFY")
        .ok()
        .and_then(|v| v.parse::<bool>().ok().or_else(|| {
            // Also accept "1", "true", "yes" (case-insensitive)
            match v.to_lowercase().as_str() {
                "1" | "true" | "yes" => Some(true),
                _ => Some(false),
            }
        }))
        .unwrap_or(false)
}

/// Vault API client configuration
#[derive(Debug, Clone)]
pub struct VaultClient {
    addr: String,
    token: String,
    client: Client,
}

impl VaultClient {
    /// Create a new Vault client from address and token
    pub fn new(addr: String, token: String) -> Result<Self> {
        Self::new_with_skip_verify(addr, token, false)
    }

    /// Create a new Vault client with option to skip TLS verification
    pub fn new_with_skip_verify(addr: String, token: String, skip_verify: bool) -> Result<Self> {
        let client = Client::builder()
            .danger_accept_invalid_certs(skip_verify)
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            addr: addr.trim_end_matches('/').to_string(),
            token,
            client,
        })
    }

    /// Create a client from environment variables
    #[allow(dead_code)]
    pub fn from_env() -> Result<Self> {
        let addr = env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());

        let token = if let Ok(token) = env::var("VAULT_TOKEN") {
            token
        } else if let Ok(token_file) = env::var("VAULT_TOKEN_FILE") {
            fs::read_to_string(&token_file)
                .with_context(|| format!("Failed to read token from file: {}", token_file))?
                .trim()
                .to_string()
        } else {
            return Err(anyhow!(
                "VAULT_TOKEN or VAULT_TOKEN_FILE must be set. Provide a token via:\n\
                 - Environment variable: export VAULT_TOKEN=hvs.xxxxx\n\
                 - Token file: export VAULT_TOKEN_FILE=/path/to/token"
            ));
        };

        Self::new(addr, token)
    }

    /// Create a client with optional parameters (for CLI)
    pub fn from_options(
        vault_addr: Option<&str>,
        vault_token: Option<&str>,
        skip_verify: bool,
    ) -> Result<Self> {
        let addr = vault_addr
            .map(|s| s.to_string())
            .or_else(|| env::var("VAULT_ADDR").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8200".to_string());

        let token = if let Some(t) = vault_token {
            t.to_string()
        } else if let Ok(t) = env::var("VAULT_TOKEN") {
            t
        } else if let Ok(token_file) = env::var("VAULT_TOKEN_FILE") {
            fs::read_to_string(&token_file)
                .with_context(|| format!("Failed to read token from file: {}", token_file))?
                .trim()
                .to_string()
        } else {
            return Err(anyhow!(
                "VAULT_TOKEN or VAULT_TOKEN_FILE must be set. Provide a token via:\n\
                 - Command-line: --vault-token hvs.xxxxx\n\
                 - Environment variable: export VAULT_TOKEN=hvs.xxxxx\n\
                 - Token file: export VAULT_TOKEN_FILE=/path/to/token"
            ));
        };

        Self::new_with_skip_verify(addr, token, skip_verify)
    }

    /// Make a GET request to a Vault API endpoint
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.addr, path);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("Failed to send request to Vault")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        if !status.is_success() {
            return Err(anyhow!(
                "Vault API request failed with status {}: {}",
                status,
                body
            ));
        }

        serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse JSON response from {}", path))
    }

    /// Make a GET request and return raw JSON Value
    pub async fn get_json(&self, path: &str) -> Result<Value> {
        self.get(path).await
    }

    /// Make a GET request and return raw text (useful for NDJSON)
    pub async fn get_text(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.addr, path);

        let response = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("Failed to send request to Vault")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        if !status.is_success() {
            return Err(anyhow!(
                "Vault API request failed with status {}: {}",
                status,
                body
            ));
        }

        Ok(body)
    }

    /// Get the Vault address
    pub fn addr(&self) -> &str {
        &self.addr
    }
}

/// Helper to extract data from Vault response wrapper
pub fn extract_data<T: DeserializeOwned>(value: Value) -> Result<T> {
    if let Some(data) = value.get("data") {
        serde_json::from_value(data.clone())
            .context("Failed to deserialize data from Vault response")
    } else {
        serde_json::from_value(value).context("Failed to deserialize Vault response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VaultClient::new(
            "http://127.0.0.1:8200".to_string(),
            "test-token".to_string(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_addr_trimming() {
        let client = VaultClient::new(
            "http://127.0.0.1:8200/".to_string(),
            "test-token".to_string(),
        )
        .unwrap();
        assert_eq!(client.addr(), "http://127.0.0.1:8200");
    }
}
