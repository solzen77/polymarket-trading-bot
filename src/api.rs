use crate::models::*;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hex;
use base64;
use log::{warn, info, error};
use std::sync::Arc;

use crate::clob_sdk_ffi;
use alloy::signers::local::LocalSigner;
use alloy::signers::Signer as _;
use alloy::primitives::Address as AlloyAddress;

// CTF (Conditional Token Framework) imports for redemption
// Based on docs: https://docs.polymarket.com/developers/builders/relayer-client#redeem-positions
use alloy::primitives::{Address as AlloyAddressPrimitive, B256, U256, Bytes};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::TransactionRequest;

// Contract interfaces for direct RPC calls (like SDK example)
use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function allowance(address owner, address spender) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IERC1155 {
        function setApprovalForAll(address operator, bool approved) external;
        function isApprovedForAll(address account, address operator) external view returns (bool);
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Parse a token ID string (hex with optional 0x prefix, or decimal) to U256 for SDK 0.4.
fn parse_token_id_u256(s: &str) -> Result<U256> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        U256::from_str_radix(&s[2..], 16).context("Invalid hex token_id")
    } else {
        U256::from_str_radix(s, 10).context("Invalid decimal token_id")
    }
}

/// Convert an Ethereum address string to U256 (left-padded 32 bytes) for SDK balance/allowance requests.
fn address_to_u256(addr: &str) -> Result<U256> {
    let a = AlloyAddressPrimitive::from_str(addr).context("Invalid address")?;
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(a.as_slice());
    Ok(U256::from_be_bytes(bytes))
}

pub struct PolymarketApi {
    client: Client,
    gamma_url: String,
    clob_url: String,
    api_key: Option<String>,
    api_secret: Option<String>,
    api_passphrase: Option<String>,
    private_key: Option<String>,
    // Proxy wallet configuration (for Polymarket proxy wallet)
    proxy_wallet_address: Option<String>,
    signature_type: Option<u8>, // 0 = EOA, 1 = Proxy, 2 = GnosisSafe
    // Track if authentication was successful at startup
    authenticated: Arc<tokio::sync::Mutex<bool>>,
    /// CLOB client handle from .so (set after authenticate())
    client_handle: Arc<tokio::sync::Mutex<Option<u64>>>,
}

impl PolymarketApi {
    pub fn new(
        gamma_url: String,
        clob_url: String,
        api_key: Option<String>,
        api_secret: Option<String>,
        api_passphrase: Option<String>,
        private_key: Option<String>,
        proxy_wallet_address: Option<String>,
        signature_type: Option<u8>,
    ) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");
        
        Self {
            client,
            gamma_url,
            clob_url,
            api_key,
            api_secret,
            api_passphrase,
            private_key,
            proxy_wallet_address,
            signature_type,
            authenticated: Arc::new(tokio::sync::Mutex::new(false)),
            client_handle: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Returns the CLOB client handle. Call after authenticate().
    async fn get_client_handle(&self) -> Result<u64> {
        let guard = self.client_handle.lock().await;
        guard.ok_or_else(|| anyhow::anyhow!("Not authenticated. Call authenticate() first."))
    }
    

    /// Authenticate with Polymarket CLOB API at startup (creates client via .so).
    /// Equivalent to JavaScript: new ClobClient(HOST, CHAIN_ID, signer, apiCreds, signatureType, funderAddress)
    pub async fn authenticate(&self) -> Result<()> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Private key is required for authentication. Please set private_key in config.json"))?;
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("api_key is required for authentication"))?;
        let api_secret = self.api_secret.as_ref()
            .ok_or_else(|| anyhow::anyhow!("api_secret is required for authentication"))?;
        let api_passphrase = self.api_passphrase.as_ref()
            .ok_or_else(|| anyhow::anyhow!("api_passphrase is required for authentication"))?;

        let sig_type = if let Some(proxy_addr) = &self.proxy_wallet_address {
            let _ = AlloyAddress::from_str(proxy_addr.trim())
                .context(format!("Invalid proxy_wallet_address: {}", proxy_addr))?;
            match self.signature_type {
                Some(1) => 1u8,
                Some(2) => 2u8,
                Some(0) => anyhow::bail!(
                    "Invalid configuration: proxy_wallet_address is set but signature_type is 0 (EOA). Use 1 (POLY_PROXY) or 2 (GNOSIS_SAFE)."
                ),
                None => {
                    crate::log_warn!("proxy_wallet_address set but signature_type not specified; defaulting to POLY_PROXY (1)");
                    1u8
                },
                Some(n) => anyhow::bail!("Invalid signature_type: {}. Must be 0, 1, or 2", n),
            }
        } else {
            match self.signature_type {
                Some(0) => 0u8,
                Some(1) | Some(2) => anyhow::bail!("signature_type {} requires proxy_wallet_address", self.signature_type.unwrap()),
                None => 0u8,
                Some(n) => anyhow::bail!("Invalid signature_type: {}. Must be 0, 1, or 2", n),
            }
        };

        let clob_url = self.clob_url.clone();
        let api_key = api_key.clone();
        let api_secret = api_secret.clone();
        let api_passphrase = api_passphrase.to_string();
        let private_key = private_key.clone();
        let funder: Option<String> = self.proxy_wallet_address.clone();
        let chain_id = clob_sdk_ffi::polygon();

        let handle = tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::client_create(
                &clob_url,
                &private_key,
                chain_id,
                funder.as_deref(),
                sig_type,
                &api_key,
                &api_secret,
                &api_passphrase,
            )
        })
        .await
        .context("authenticate spawn_blocking")?
        .context("Failed to authenticate with CLOB API. Check API credentials and private_key.")?;

        *self.client_handle.lock().await = Some(handle);
        *self.authenticated.lock().await = true;

        crate::log_ok!("Authenticated with Polymarket CLOB API");
        crate::log_info!("  Private key and API credentials valid");
        if let Some(proxy_addr) = &self.proxy_wallet_address {
            crate::log_info!("  Proxy wallet: {}", proxy_addr);
        } else {
            crate::log_info!("  Trading account: EOA (private key)");
        }
        Ok(())
    }

    /// Generate HMAC-SHA256 signature for authenticated requests
    fn generate_signature(
        &self,
        method: &str,
        path: &str,
        body: &str,
        timestamp: u64,
    ) -> Result<String> {
        let secret = self.api_secret.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API secret is required for authenticated requests"))?;
        
        // Create message: method + path + body + timestamp
        let message = format!("{}{}{}{}", method, path, body, timestamp);
        
        // Try to decode secret from base64url first (Builder API uses base64url encoding)
        // Base64url uses - and _ instead of + and /, making it URL-safe
        // Then try standard base64, then fall back to raw bytes
        let secret_bytes = {
            use base64::engine::general_purpose;
            use base64::Engine;
            
            // First try base64url (URL_SAFE engine)
            if let Ok(bytes) = general_purpose::URL_SAFE.decode(secret) {
                bytes
            }
            // Then try standard base64
            else if let Ok(bytes) = general_purpose::STANDARD.decode(secret) {
                bytes
            }
            // Finally, use raw bytes if both fail
            else {
                secret.as_bytes().to_vec()
            }
        };
        
        // Create HMAC-SHA256 signature
        let mut mac = HmacSha256::new_from_slice(&secret_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create HMAC: {}", e))?;
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());
        
        Ok(signature)
    }

    /// Add authentication headers to a request
    fn add_auth_headers(
        &self,
        request: reqwest::RequestBuilder,
        method: &str,
        path: &str,
        body: &str,
    ) -> Result<reqwest::RequestBuilder> {
        // Only add auth headers if we have all required credentials
        if self.api_key.is_none() || self.api_secret.is_none() || self.api_passphrase.is_none() {
            return Ok(request);
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let signature = self.generate_signature(method, path, body, timestamp)?;
        
        let request = request
            .header("POLY_API_KEY", self.api_key.as_ref().unwrap())
            .header("POLY_SIGNATURE", signature)
            .header("POLY_TIMESTAMP", timestamp.to_string())
            .header("POLY_PASSPHRASE", self.api_passphrase.as_ref().unwrap());
        
        Ok(request)
    }

    /// Get all active markets (using events endpoint)
    pub async fn get_all_active_markets(&self, limit: u32) -> Result<Vec<Market>> {
        let url = format!("{}/events", self.gamma_url);
        let limit_str = limit.to_string();
        let mut params = HashMap::new();
        params.insert("active", "true");
        params.insert("closed", "false");
        params.insert("limit", &limit_str);

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .context("Failed to fetch all active markets")?;

        let status = response.status();
        let json: Value = response.json().await.context("Failed to parse markets response")?;
        
        if !status.is_success() {
            log::warn!("Get all active markets API returned error status {}: {}", status, serde_json::to_string(&json).unwrap_or_default());
            anyhow::bail!("API returned error status {}: {}", status, serde_json::to_string(&json).unwrap_or_default());
        }
        
        // Extract markets from events - events contain markets
        let mut all_markets = Vec::new();
        
        if let Some(events) = json.as_array() {
            for event in events {
                if let Some(markets) = event.get("markets").and_then(|m| m.as_array()) {
                    for market_json in markets {
                        if let Ok(market) = serde_json::from_value::<Market>(market_json.clone()) {
                            all_markets.push(market);
                        }
                    }
                }
            }
        } else if let Some(data) = json.get("data") {
            if let Some(events) = data.as_array() {
                for event in events {
                    if let Some(markets) = event.get("markets").and_then(|m| m.as_array()) {
                        for market_json in markets {
                            if let Ok(market) = serde_json::from_value::<Market>(market_json.clone()) {
                                all_markets.push(market);
                            }
                        }
                    }
                }
            }
        }
        
        log::debug!("Fetched {} active markets from events endpoint", all_markets.len());
        Ok(all_markets)
    }

    /// Get market by slug (e.g., "btc-updown-15m-1767726000")
    /// The API returns an event object with a markets array
    pub async fn get_market_by_slug(&self, slug: &str) -> Result<Market> {
        let url = format!("{}/events/slug/{}", self.gamma_url, slug);
        
        let response = self.client.get(&url).send().await
            .context(format!("Failed to fetch market by slug: {}", slug))?;
        
        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("Failed to fetch market by slug: {} (status: {})", slug, status);
        }
        
        let json: Value = response.json().await
            .context("Failed to parse market response")?;
        
        // The response is an event object with a "markets" array
        // Extract the first market from the markets array
        if let Some(markets) = json.get("markets").and_then(|m| m.as_array()) {
            if let Some(market_json) = markets.first() {
                // Try to deserialize the market
                if let Ok(market) = serde_json::from_value::<Market>(market_json.clone()) {
                    return Ok(market);
                }
            }
        }
        
        anyhow::bail!("Invalid market response format: no markets array found")
    }

    /// Get order book for a specific token
    pub async fn get_orderbook(&self, token_id: &str) -> Result<OrderBook> {
        let url = format!("{}/book", self.clob_url);
        let params = [("token_id", token_id)];

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .context("Failed to fetch orderbook")?;

        let orderbook: OrderBook = response
            .json()
            .await
            .context("Failed to parse orderbook")?;

        Ok(orderbook)
    }

    /// Get market details by condition ID
    pub async fn get_market(&self, condition_id: &str) -> Result<MarketDetails> {
        let url = format!("{}/markets/{}", self.clob_url, condition_id);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context(format!("Failed to fetch market for condition_id: {}", condition_id))?;

        let status = response.status();
        
        if !status.is_success() {
            anyhow::bail!("Failed to fetch market (status: {})", status);
        }

        let json_text = response.text().await
            .context("Failed to read response body")?;

        let market: MarketDetails = serde_json::from_str(&json_text)
            .map_err(|e| {
                log::error!("Failed to parse market response: {}. Response was: {}", e, json_text);
                anyhow::anyhow!("Failed to parse market response: {}", e)
            })?;

        Ok(market)
    }

    /// Get price for a token (for trading)
    /// side: "BUY" or "SELL"
    pub async fn get_price(&self, token_id: &str, side: &str) -> Result<rust_decimal::Decimal> {
        let url = format!("{}/price", self.clob_url);
        let params = [
            ("side", side),
            ("token_id", token_id),
        ];

        log::debug!("Fetching price from: {}?side={}&token_id={}", url, side, token_id);

        let response = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .context("Failed to fetch price")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("Failed to fetch price (status: {})", status);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse price response")?;

        let price_str = json.get("price")
            .and_then(|p| p.as_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid price response format"))?;

        let price = rust_decimal::Decimal::from_str(price_str)
            .context(format!("Failed to parse price: {}", price_str))?;

        log::debug!("Price for token {} (side={}): {}", token_id, side, price);

        Ok(price)
    }

    /// Get best bid/ask prices for a token (from orderbook)
    pub async fn get_best_price(&self, token_id: &str) -> Result<Option<TokenPrice>> {
        let orderbook = self.get_orderbook(token_id).await?;
        
        let best_bid = orderbook.bids.first().map(|b| b.price);
        let best_ask = orderbook.asks.first().map(|a| a.price);

        if best_ask.is_some() {
            Ok(Some(TokenPrice {
                token_id: token_id.to_string(),
                bid: best_bid,
                ask: best_ask,
            }))
        } else {
            Ok(None)
        }
    }

    /// Place an order using the official SDK with proper private key signing
    /// 
    /// This method uses the official polymarket-client-sdk to:
    /// 1. Create signer from private key
    /// 2. Use authenticated CLOB client (from .so)
    /// 3. Post limit order via FFI
    /// Equivalent to JavaScript: client.createAndPostOrder(userOrder)
    pub async fn place_order(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let handle = self.get_client_handle().await?;
        let token_id = order.token_id.clone();
        let side = order.side.clone();
        let price = order.price.clone();
        let size = order.size.clone();

        crate::log_action!("Placing order: {} {} {} @ {}", order.side, order.size, order.token_id, order.price);

        let order_id = tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::post_limit_order(handle, &token_id, &side, &price, &size)
        })
        .await
        .context("place_order spawn_blocking")??;

        crate::log_ok!("Order placed successfully. Order ID: {}", order_id);
        Ok(OrderResponse {
            order_id: Some(order_id.clone()),
            status: "LIVE".to_string(),
            message: Some(format!("Order placed successfully. Order ID: {}", order_id)),
        })
    }

    /// Discover current BTC or ETH 15-minute market
    /// Similar to main bot's discover_market function
    pub async fn discover_current_market(&self, asset: &str) -> Result<Option<String>> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Calculate current 15-minute period
        let current_period = (current_time / 900) * 900;
        
        // Try to find market for current period and a few previous periods (in case market is slightly delayed)
        for offset in 0..=2 {
            let period_to_check = current_period - (offset * 900);
            let slug = format!("{}-updown-15m-{}", asset.to_lowercase(), period_to_check);
            
            // Try to get market by slug
            if let Ok(market) = self.get_market_by_slug(&slug).await {
                return Ok(Some(market.condition_id));
            }
        }
        
        // If slug-based discovery fails, try searching active markets
        if let Ok(markets) = self.get_all_active_markets(50).await {
            let asset_upper = asset.to_uppercase();
            for market in markets {
                // Check if this is a BTC/ETH 15-minute market
                if market.slug.contains(&format!("{}-updown-15m", asset.to_lowercase())) 
                    || market.question.to_uppercase().contains(&format!("{} 15", asset_upper)) {
                    return Ok(Some(market.condition_id));
                }
            }
        }
        
        Ok(None)
    }

    /// Get tokens in portfolio for BTC markets only (no ETH/Solana/XRP). Use for redeem script when other markets are disabled.
    pub async fn get_portfolio_tokens_btc_only(&self) -> Result<Vec<(String, f64, String, String)>> {
        let mut tokens_with_balance = Vec::new();
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        println!("🔍 Scanning BTC markets only (current + recent past)...");
        for offset in 0..=10 {
            let period_to_check = (current_time / 900) * 900 - (offset * 900);
            let slug = format!("btc-updown-15m-{}", period_to_check);
            if let Ok(market) = self.get_market_by_slug(&slug).await {
                let condition_id = market.condition_id.clone();
                println!("   📊 Checking BTC market: {} (period: {})", &condition_id[..16.min(condition_id.len())], period_to_check);
                if let Ok(market_details) = self.get_market(&condition_id).await {
                    for token in &market_details.tokens {
                        if let Ok(balance) = self.check_balance_only(&token.token_id).await {
                            let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                            let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                            if balance_f64 > 0.0 {
                                let description = format!("BTC {} (period: {})", token.outcome, period_to_check);
                                tokens_with_balance.push((token.token_id.clone(), balance_f64, description, condition_id.clone()));
                                println!("      ✅ Found token with balance: {} shares", balance_f64);
                            }
                        }
                    }
                }
            }
        }
        Ok(tokens_with_balance)
    }

    /// Get all tokens in portfolio with balance > 0
    /// Get all tokens in portfolio with balance > 0, checking recent markets (not just current)
    /// Checks current market and recent past markets (up to 10 periods = 2.5 hours) to find tokens from resolved markets
    pub async fn get_portfolio_tokens_all(&self, btc_condition_id: Option<&str>, eth_condition_id: Option<&str>) -> Result<Vec<(String, f64, String, String)>> {
        let mut tokens_with_balance = Vec::new();
        
        // Check BTC markets (current + recent past)
        println!("🔍 Scanning BTC markets (current + recent past)...");
        for offset in 0..=10 { // Check last 10 periods (2.5 hours)
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let period_to_check = (current_time / 900) * 900 - (offset * 900);
            let slug = format!("btc-updown-15m-{}", period_to_check);
            
            if let Ok(market) = self.get_market_by_slug(&slug).await {
                let condition_id = market.condition_id.clone();
                println!("   📊 Checking BTC market: {} (period: {})", &condition_id[..16], period_to_check);
                
                if let Ok(market_details) = self.get_market(&condition_id).await {
                    for token in &market_details.tokens {
                        match self.check_balance_only(&token.token_id).await {
                            Ok(balance) => {
                                let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                                let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                                if balance_f64 > 0.0 {
                                    let description = format!("BTC {} (period: {})", token.outcome, period_to_check);
                                    tokens_with_balance.push((token.token_id.clone(), balance_f64, description, condition_id.clone()));
                                    println!("      ✅ Found token with balance: {} shares", balance_f64);
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
        
        // Check ETH markets (current + recent past)
        println!("🔍 Scanning ETH markets (current + recent past)...");
        for offset in 0..=10 { // Check last 10 periods (2.5 hours)
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let period_to_check = (current_time / 900) * 900 - (offset * 900);
            let slug = format!("eth-updown-15m-{}", period_to_check);
            
            if let Ok(market) = self.get_market_by_slug(&slug).await {
                let condition_id = market.condition_id.clone();
                println!("   📊 Checking ETH market: {} (period: {})", &condition_id[..16], period_to_check);
                
                if let Ok(market_details) = self.get_market(&condition_id).await {
                    for token in &market_details.tokens {
                        match self.check_balance_only(&token.token_id).await {
                            Ok(balance) => {
                                let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                                let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                                if balance_f64 > 0.0 {
                                    let description = format!("ETH {} (period: {})", token.outcome, period_to_check);
                                    tokens_with_balance.push((token.token_id.clone(), balance_f64, description, condition_id.clone()));
                                    println!("      ✅ Found token with balance: {} shares", balance_f64);
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
        
        // Check Solana markets (current + recent past)
        println!("🔍 Scanning Solana markets (current + recent past)...");
        for offset in 0..=10 { // Check last 10 periods (2.5 hours)
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let period_to_check = (current_time / 900) * 900 - (offset * 900);
            
            // Try both slug formats
            let slugs = vec![
                format!("solana-updown-15m-{}", period_to_check),
                format!("sol-updown-15m-{}", period_to_check),
            ];
            
            for slug in slugs {
                if let Ok(market) = self.get_market_by_slug(&slug).await {
                    let condition_id = market.condition_id.clone();
                    println!("   📊 Checking Solana market: {} (period: {})", &condition_id[..16], period_to_check);
                    
                    if let Ok(market_details) = self.get_market(&condition_id).await {
                        for token in &market_details.tokens {
                            match self.check_balance_only(&token.token_id).await {
                                Ok(balance) => {
                                    let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                                    let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                                    if balance_f64 > 0.0 {
                                        let description = format!("Solana {} (period: {})", token.outcome, period_to_check);
                                        tokens_with_balance.push((token.token_id.clone(), balance_f64, description, condition_id.clone()));
                                        println!("      ✅ Found token with balance: {} shares", balance_f64);
                                    }
                                }
                                Err(_) => continue,
                            }
                        }
                    }
                    break; // Found a valid market, no need to try other slug format
                }
            }
        }
        
        Ok(tokens_with_balance)
    }

    /// Automatically discovers current BTC and ETH markets if condition IDs are not provided
    pub async fn get_portfolio_tokens(&self, btc_condition_id: Option<&str>, eth_condition_id: Option<&str>) -> Result<Vec<(String, f64, String)>> {
        let mut tokens_with_balance = Vec::new();
        
        // Discover BTC market if not provided
        let btc_condition_id_owned: Option<String> = if let Some(id) = btc_condition_id {
            Some(id.to_string())
        } else {
            println!("🔍 Discovering current BTC 15-minute market...");
            match self.discover_current_market("BTC").await {
                Ok(Some(id)) => {
                    println!("   ✅ Found BTC market: {}", id);
                    Some(id)
                }
                Ok(None) => {
                    println!("   ⚠️  Could not find current BTC market");
                    None
                }
                Err(e) => {
                    eprintln!("   ❌ Error discovering BTC market: {}", e);
                    None
                }
            }
        };
        
        // Discover ETH market if not provided
        let eth_condition_id_owned: Option<String> = if let Some(id) = eth_condition_id {
            Some(id.to_string())
        } else {
            println!("🔍 Discovering current ETH 15-minute market...");
            match self.discover_current_market("ETH").await {
                Ok(Some(id)) => {
                    println!("   ✅ Found ETH market: {}", id);
                    Some(id)
                }
                Ok(None) => {
                    println!("   ⚠️  Could not find current ETH market");
                    None
                }
                Err(e) => {
                    eprintln!("   ❌ Error discovering ETH market: {}", e);
                    None
                }
            }
        };
        
        // Check BTC market tokens
        if let Some(ref btc_condition_id) = btc_condition_id_owned {
            println!("📊 Checking BTC market tokens for condition: {}", btc_condition_id);
            if let Ok(btc_market) = self.get_market(btc_condition_id).await {
                println!("   ✅ Found {} tokens in BTC market", btc_market.tokens.len());
                for token in &btc_market.tokens {
                    println!("   🔍 Checking balance for token: {} ({})", token.outcome, &token.token_id[..16]);
                    match self.check_balance_allowance(&token.token_id).await {
                        Ok((balance, _)) => {
                            let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                            let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                            println!("      Balance: {:.6} shares", balance_f64);
                            if balance_f64 > 0.0 {
                                tokens_with_balance.push((token.token_id.clone(), balance_f64, format!("BTC {}", token.outcome)));
                                println!("      ✅ Found token with balance!");
                            }
                        }
                        Err(e) => {
                            println!("      ⚠️  Failed to check balance: {}", e);
                            // Skip tokens that fail balance check (might not exist or network error)
                            continue;
                        }
                    }
                }
            } else {
                eprintln!("   ❌ Failed to fetch BTC market details");
            }
        }
        
        // Check ETH market tokens
        if let Some(ref eth_condition_id) = eth_condition_id_owned {
            println!("📊 Checking ETH market tokens for condition: {}", eth_condition_id);
            if let Ok(eth_market) = self.get_market(eth_condition_id).await {
                println!("   ✅ Found {} tokens in ETH market", eth_market.tokens.len());
                for token in &eth_market.tokens {
                    println!("   🔍 Checking balance for token: {} ({})", token.outcome, &token.token_id[..16]);
                    match self.check_balance_allowance(&token.token_id).await {
                        Ok((balance, _)) => {
                            let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                            let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                            println!("      Balance: {:.6} shares", balance_f64);
                            if balance_f64 > 0.0 {
                                tokens_with_balance.push((token.token_id.clone(), balance_f64, format!("ETH {}", token.outcome)));
                                println!("      ✅ Found token with balance!");
                            }
                        }
                        Err(e) => {
                            println!("      ⚠️  Failed to check balance: {}", e);
                            // Skip tokens that fail balance check
                            continue;
                        }
                    }
                }
            } else {
                eprintln!("   ❌ Failed to fetch ETH market details");
            }
        }
        
        Ok(tokens_with_balance)
    }

    /// Check USDC balance and allowance for buying tokens (via .so).
    /// Returns (usdc_balance, usdc_allowance) as Decimal values.
    pub async fn check_usdc_balance_allowance(&self) -> Result<(rust_decimal::Decimal, rust_decimal::Decimal)> {
        const USDC_ADDRESS: &str = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";
        let usdc_token_id = address_to_u256(USDC_ADDRESS)?;
        let usdc_token_id_str = format!("0x{:064x}", usdc_token_id);

        let handle = self.get_client_handle().await?;
        let (balance_str, allowance_str) = tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::balance_allowance(handle, &usdc_token_id_str, "Collateral")
        })
        .await
        .context("check_usdc_balance_allowance spawn_blocking")??;

        let balance = rust_decimal::Decimal::from_str(&balance_str).context("parse USDC balance")?;
        let allowance = rust_decimal::Decimal::from_str(&allowance_str).context("parse USDC allowance")?;
        Ok((balance, allowance))
    }

    /// Check token balance only (via .so). Returns balance as Decimal.
    pub async fn check_balance_only(&self, token_id: &str) -> Result<rust_decimal::Decimal> {
        let handle = self.get_client_handle().await?;
        let token_id = token_id.to_string();
        let (balance_str, _) = tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::balance_allowance(handle, &token_id, "Conditional")
        })
        .await
        .context("check_balance_only spawn_blocking")??;
        rust_decimal::Decimal::from_str(&balance_str).context("parse balance")
    }

    /// Check token balance and allowance before selling (via .so). Returns (balance, allowance) as Decimal.
    pub async fn check_balance_allowance(&self, token_id: &str) -> Result<(rust_decimal::Decimal, rust_decimal::Decimal)> {
        let handle = self.get_client_handle().await?;
        let token_id = token_id.to_string();
        let (balance_str, allowance_str) = tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::balance_allowance(handle, &token_id, "Conditional")
        })
        .await
        .context("check_balance_allowance spawn_blocking")??;

        let balance = rust_decimal::Decimal::from_str(&balance_str).context("parse balance")?;
        let allowance = rust_decimal::Decimal::from_str(&allowance_str).unwrap_or(rust_decimal::Decimal::ZERO);

        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config"))?;
        let allowance_f64 = f64::try_from(allowance / rust_decimal::Decimal::from(1_000_000u64)).unwrap_or(0.0);
        crate::log_info!("  Exchange allowance: {:.6} shares ({:#x})", allowance_f64, config.exchange);

        let is_approved_for_all = match self.check_is_approved_for_all().await {
            Ok(true) => {
                crate::log_ok!("  setApprovalForAll: SET (Exchange can spend all tokens)");
                true
            }
            Ok(false) => {
                crate::log_warn!("  setApprovalForAll: NOT SET (Exchange cannot spend tokens)");
                false
            }
            Err(e) => {
                crate::log_warn!("  Could not check setApprovalForAll: {}", e);
                false
            }
        };
        if is_approved_for_all {
            crate::log_info!("  setApprovalForAll is SET; per-token allowance ({:.6}) ignored for selling", allowance_f64);
        }

        Ok((balance, allowance))
    }

    /// Refresh cached allowance for outcome token before selling (via .so). Call before place_market_order(..., "SELL", ...).
    pub async fn update_balance_allowance_for_sell(&self, token_id: &str) -> Result<()> {
        let handle = self.get_client_handle().await?;
        let token_id = token_id.to_string();
        tokio::task::spawn_blocking(move || {
            clob_sdk_ffi::update_balance_allowance(handle, &token_id, "Conditional")
        })
        .await
        .context("update_balance_allowance_for_sell spawn_blocking")??;
        Ok(())
    }

    /// Get the CLOB contract address for Polygon using SDK's contract_config
    /// This is the Exchange contract address that needs to be approved via setApprovalForAll
    fn get_clob_contract_address(&self) -> Result<String> {
        // Use SDK's contract_config to get the correct Exchange contract address
        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config from SDK"))?;
        Ok(format!("{:#x}", config.exchange))
    }

    /// Get the CTF contract address for Polygon using SDK's contract_config
    /// This is where we call setApprovalForAll()
    fn get_ctf_contract_address(&self) -> Result<String> {
        // Use SDK's contract_config to get the correct CTF contract address
        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config from SDK"))?;
        Ok(format!("{:#x}", config.conditional_tokens))
    }

    /// Check if setApprovalForAll was already set for the Exchange contract
    /// Returns true if the Exchange is already approved to manage all tokens
    pub async fn check_is_approved_for_all(&self) -> Result<bool> {
        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config from SDK"))?;
        
        let ctf_contract_address = config.conditional_tokens;
        let exchange_address = config.exchange;
        
        // Determine which address to check (proxy wallet or EOA)
        let account_to_check = if let Some(proxy_addr) = &self.proxy_wallet_address {
            AlloyAddress::from_str(proxy_addr.trim())
                .context(format!("Failed to parse proxy_wallet_address: {}", proxy_addr))?
        } else {
            let private_key = self.private_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Private key required to check approval"))?;
            let signer = LocalSigner::from_str(private_key)
                .context("Failed to create signer from private key")?
                .with_chain_id(Some(clob_sdk_ffi::polygon()));
            signer.address()
        };
        
        const RPC_URL: &str = "https://polygon-rpc.com";
        let provider = ProviderBuilder::new()
            .connect(RPC_URL)
            .await
            .context("Failed to connect to Polygon RPC")?;
        
        let ctf = IERC1155::new(ctf_contract_address, provider);
        
        let approved = ctf
            .isApprovedForAll(account_to_check, exchange_address)
            .call()
            .await
            .context("Failed to check isApprovedForAll")?;
        
        Ok(approved)
    }

    /// Check all approvals for all contracts (like SDK's check_approvals example)
    /// Returns a vector of (contract_name, usdc_approved, ctf_approved) tuples
    pub async fn check_all_approvals(&self) -> Result<Vec<(String, bool, bool)>> {
        const RPC_URL: &str = "https://polygon-rpc.com";
        const USDC_ADDRESS: &str = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";

        let usdc_address = AlloyAddress::from_str(USDC_ADDRESS).context("USDC address")?;
        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config from SDK"))?;
        let neg_risk_config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), true)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get neg risk contract config from SDK"))?;
        
        // Determine which address to check (proxy wallet or EOA)
        let account_to_check = if let Some(proxy_addr) = &self.proxy_wallet_address {
            AlloyAddress::from_str(proxy_addr.trim())
                .context(format!("Failed to parse proxy_wallet_address: {}", proxy_addr))?
        } else {
            let private_key = self.private_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Private key required to check approval"))?;
            let signer = LocalSigner::from_str(private_key)
                .context("Failed to create signer from private key")?
                .with_chain_id(Some(clob_sdk_ffi::polygon()));
            signer.address()
        };
        
        let provider = ProviderBuilder::new()
            .connect(RPC_URL)
            .await
            .context("Failed to connect to Polygon RPC")?;
        
        let usdc = IERC20::new(usdc_address, provider.clone());
        let ctf = IERC1155::new(config.conditional_tokens, provider.clone());

        // Collect all contracts that need approval
        let mut targets: Vec<(&str, AlloyAddress)> = vec![
            ("CTF Exchange", config.exchange),
            ("Neg Risk CTF Exchange", neg_risk_config.exchange),
        ];
        
        if let Some(adapter) = neg_risk_config.neg_risk_adapter {
            targets.push(("Neg Risk Adapter", adapter));
        }
        
        let mut results = Vec::new();
        
        for (name, target) in &targets {
            let usdc_approved = usdc
                .allowance(account_to_check, *target)
                .call()
                .await
                .map(|allowance| allowance > U256::ZERO)
                .unwrap_or(false);
            
            let ctf_approved = ctf
                .isApprovedForAll(account_to_check, *target)
                .call()
                .await
                .unwrap_or(false);
            
            results.push((name.to_string(), usdc_approved, ctf_approved));
        }
        
        Ok(results)
    }

    /// Approve the CLOB contract for ALL conditional tokens using CTF contract's setApprovalForAll()
    /// This is the recommended way to avoid allowance errors for all tokens at once
    /// Based on SDK example: https://github.com/Polymarket/rs-clob-client/blob/main/examples/approvals.rs
    /// 
    /// For proxy wallets: Uses Polymarket's relayer to execute the transaction (gasless)
    /// For EOA wallets: Uses direct RPC call
    /// 
    /// IMPORTANT: The wallet that needs MATIC for gas:
    /// - If using proxy_wallet_address: Uses relayer (gasless, no MATIC needed)
    /// - If NOT using proxy_wallet_address: The wallet derived from private_key needs MATIC
    pub async fn set_approval_for_all_clob(&self) -> Result<()> {
        // Get addresses from SDK's contract_config
        // Based on SDK example: https://github.com/Polymarket/rs-clob-client/blob/main/examples/approvals.rs
        // - config.conditional_tokens = CTF contract (where we call setApprovalForAll)
        // - config.exchange = CTF Exchange (the operator we approve)
        let config = clob_sdk_ffi::contract_config(clob_sdk_ffi::polygon(), false)?
            .ok_or_else(|| anyhow::anyhow!("Failed to get contract config from SDK"))?;
        
        let ctf_contract_address = config.conditional_tokens;
        let exchange_address = config.exchange;
        
        eprintln!("🔐 Setting approval for all tokens using CTF contract's setApprovalForAll()");
        eprintln!("   CTF Contract (conditional_tokens): {:#x}", ctf_contract_address);
        eprintln!("   CTF Exchange (exchange/operator): {:#x}", exchange_address);
        eprintln!("   This will approve the Exchange contract to manage ALL your conditional tokens");
        
        // For proxy wallets, use relayer (gasless transactions)
        // For EOA wallets, use direct RPC call
        if let Some(proxy_addr) = &self.proxy_wallet_address {
            eprintln!("   🔄 Using Polymarket relayer for proxy wallet (gasless transaction)");
            eprintln!("   Proxy wallet: {}", proxy_addr);
            
            // Use relayer to execute setApprovalForAll from proxy wallet
            // Based on: https://docs.polymarket.com/developers/builders/relayer-client
            self.set_approval_for_all_via_relayer(ctf_contract_address, exchange_address).await
        } else {
            eprintln!("   🔄 Using direct RPC call for EOA wallet");
            
            // Check if we have a private key (required for signing)
            let private_key = self.private_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Private key is required for token approval. Please set private_key in config.json"))?;
            
            // Create signer from private key
            let signer = LocalSigner::from_str(private_key)
                .context("Failed to create signer from private key. Ensure private_key is a valid hex string.")?
                .with_chain_id(Some(clob_sdk_ffi::polygon()));
            
            let signer_address = signer.address();
            eprintln!("   💰 Wallet that needs MATIC for gas: {:#x}", signer_address);
            
            // Use direct RPC call like SDK example (instead of relayer)
            // Based on: https://github.com/Polymarket/rs-clob-client/blob/main/examples/approvals.rs
            const RPC_URL: &str = "https://polygon-rpc.com";
            
            let provider = ProviderBuilder::new()
                .wallet(signer.clone())
                .connect(RPC_URL)
                .await
                .context("Failed to connect to Polygon RPC")?;
            
            // Create IERC1155 contract instance
            let ctf = IERC1155::new(ctf_contract_address, provider.clone());
            
            eprintln!("   📤 Sending setApprovalForAll transaction via direct RPC call...");
            
            // Call setApprovalForAll directly (like SDK example)
            let tx_hash = ctf
                .setApprovalForAll(exchange_address, true)
                .send()
                .await
                .context("Failed to send setApprovalForAll transaction")?
                .watch()
                .await
                .context("Failed to watch setApprovalForAll transaction")?;
            
            eprintln!("   ✅ Successfully sent setApprovalForAll transaction!");
            eprintln!("   Transaction Hash: {:#x}", tx_hash);
            
            Ok(())
        }
    }
    
    /// Set approval for all tokens via Polymarket relayer (for proxy wallets)
    /// Based on: https://docs.polymarket.com/developers/builders/relayer-client
    /// 
    /// NOTE: For signature_type 2 (GNOSIS_SAFE), the relayer expects a complex Safe transaction format
    /// with nonce, Safe address derivation, struct hash signing, etc. This implementation uses a
    /// simpler format that may work for signature_type 1 (POLY_PROXY). If you get 400/401 errors
    /// with signature_type 2, the full Safe transaction flow needs to be implemented.
    async fn set_approval_for_all_via_relayer(
        &self,
        ctf_contract_address: AlloyAddress,
        exchange_address: AlloyAddress,
    ) -> Result<()> {
        // Check signature_type - warn if using GNOSIS_SAFE (type 2) as it may need different format
        if let Some(2) = self.signature_type {
            eprintln!("   ⚠️  Using signature_type 2 (GNOSIS_SAFE) - relayer may require Safe transaction format");
            eprintln!("   💡 If this fails, the full Safe transaction flow (nonce, Safe address, struct hash) may be needed");
        }
        
        // Function signature: setApprovalForAll(address operator, bool approved)
        // Function selector: keccak256("setApprovalForAll(address,bool)")[0:4] = 0xa22cb465
        let function_selector = hex::decode("a22cb465")
            .context("Failed to decode function selector")?;
        
        // Encode parameters: (address operator, bool approved)
        let mut encoded_params = Vec::new();
        
        // Encode operator address (20 bytes, left-padded to 32 bytes)
        let mut operator_bytes = [0u8; 32];
        operator_bytes[12..].copy_from_slice(exchange_address.as_slice());
        encoded_params.extend_from_slice(&operator_bytes);
        
        // Encode approved (bool) - true = 1, padded to 32 bytes
        let approved_bytes = U256::from(1u64).to_be_bytes::<32>();
        encoded_params.extend_from_slice(&approved_bytes);
        
        // Combine function selector with encoded parameters
        let mut call_data = function_selector;
        call_data.extend_from_slice(&encoded_params);
        
        let call_data_hex = format!("0x{}", hex::encode(&call_data));
        
        eprintln!("   📝 Encoded call data: {}", call_data_hex);
        
        // Use relayer for gasless transaction. The /execute path returns 404; the
        // builder-relayer-client uses POST /submit. See: Polymarket/builder-relayer-client
        const RELAYER_SUBMIT: &str = "https://relayer-v2.polymarket.com/submit";
        
        eprintln!("   📤 Sending setApprovalForAll transaction via relayer (POST /submit)...");
        
        // Build transaction for relayer
        // NOTE: This simple format works for POLY_PROXY (type 1). For GNOSIS_SAFE (type 2),
        // the relayer may expect: { from, to, proxyWallet, data, nonce, signature, signatureParams, type: "SAFE", metadata }
        let ctf_address_str = format!("{:#x}", ctf_contract_address);
        let transaction = serde_json::json!({
            "to": ctf_address_str,
            "data": call_data_hex,
            "value": "0"
        });
        
        let relayer_request = serde_json::json!({
            "transactions": [transaction],
            "description": format!("Set approval for all tokens - approve Exchange contract {:#x}", exchange_address)
        });
        
        // Add authentication headers (Builder API credentials)
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for relayer. Please set api_key in config.json"))?;
        let api_secret = self.api_secret.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API secret required for relayer. Please set api_secret in config.json"))?;
        let api_passphrase = self.api_passphrase.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API passphrase required for relayer. Please set api_passphrase in config.json"))?;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        
        let body_string = serde_json::to_string(&relayer_request)
            .context("Failed to serialize relayer request")?;
        
        // Generate HMAC signature for relayer authentication. Path must match the
        // endpoint: /submit (builder-relayer-client uses /submit, not /execute).
        let url_path = "/submit";
        let message = format!("POST{}{}{}", url_path, body_string, timestamp);
        
        // Try to decode secret from base64url first (Builder API uses base64url encoding)
        // Base64url uses - and _ instead of + and /, making it URL-safe
        // Then try standard base64, then fall back to raw bytes
        let secret_bytes = {
            use base64::engine::general_purpose;
            use base64::Engine;
            
            // First try base64url (URL_SAFE engine)
            if let Ok(bytes) = general_purpose::URL_SAFE.decode(api_secret) {
                bytes
            }
            // Then try standard base64
            else if let Ok(bytes) = general_purpose::STANDARD.decode(api_secret) {
                bytes
            }
            // Finally, use raw bytes if both fail
            else {
                api_secret.as_bytes().to_vec()
            }
        };
        
        let mut mac = HmacSha256::new_from_slice(&secret_bytes)
            .context("Failed to create HMAC")?;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        
        // Send request to relayer
        let response = self.client
            .post(RELAYER_SUBMIT)
            .header("User-Agent", "polymarket-trading-bot/1.0")
            .header("POLY_BUILDER_API_KEY", api_key)
            .header("POLY_BUILDER_TIMESTAMP", &timestamp)
            .header("POLY_BUILDER_PASSPHRASE", api_passphrase)
            .header("POLY_BUILDER_SIGNATURE", &signature)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&relayer_request)
            .send()
            .await
            .context("Failed to send setApprovalForAll request to relayer")?;
        
        let status = response.status();
        let response_text = response.text().await
            .context("Failed to read relayer response")?;
        
        if !status.is_success() {
            let sig_type_hint = if self.signature_type == Some(2) {
                "\n\n   💡 For signature_type 2 (GNOSIS_SAFE), the relayer expects a Safe transaction format:\n\
                  - Get nonce from /nonce endpoint\n\
                  - Derive Safe address from signer\n\
                  - Build SafeTx struct hash\n\
                  - Sign and pack signature\n\
                  - Send: { from, to, proxyWallet, data, nonce, signature, signatureParams, type: \"SAFE\", metadata }\n\
                  \n\
                  Consider using signature_type 1 (POLY_PROXY) if possible, or implement the full Safe flow."
            } else {
                ""
            };
            
            anyhow::bail!(
                "Relayer rejected setApprovalForAll request (status: {}): {}\n\
                \n\
                CTF Contract Address: {:#x}\n\
                Exchange Contract Address: {:#x}\n\
                Signature Type: {:?}\n\
                \n\
                This may be a relayer endpoint issue, authentication problem, or request format mismatch.\n\
                Please verify your Builder API credentials are correct.{}",
                status, response_text, ctf_contract_address, exchange_address, self.signature_type, sig_type_hint
            );
        }
        
        // Parse relayer response
        let relayer_response: serde_json::Value = serde_json::from_str(&response_text)
            .context("Failed to parse relayer response")?;
        
        let transaction_id = relayer_response["transactionID"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing transactionID in relayer response"))?;
        
        eprintln!("   ✅ Successfully sent setApprovalForAll transaction via relayer!");
        eprintln!("   Transaction ID: {}", transaction_id);
        eprintln!("   💡 The relayer will execute this transaction from your proxy wallet (gasless)");
        
        // Wait for transaction confirmation (like TypeScript SDK's response.wait())
        eprintln!("   ⏳ Waiting for transaction confirmation...");
        self.wait_for_relayer_transaction(transaction_id).await?;
        
        Ok(())
    }
    
    /// Wait for relayer transaction to be confirmed (like TypeScript SDK's response.wait())
    /// Polls the relayer status endpoint until transaction reaches STATE_CONFIRMED or STATE_FAILED
    async fn wait_for_relayer_transaction(&self, transaction_id: &str) -> Result<String> {
        // Based on TypeScript SDK pattern: response.wait() returns transactionHash
        // Relayer states: STATE_NEW, STATE_EXECUTED, STATE_MINE, STATE_CONFIRMED, STATE_FAILED, STATE_INVALID
        let status_url = format!("https://relayer-v2.polymarket.com/transaction/{}", transaction_id);
        
        // Poll for transaction confirmation (with timeout)
        let max_wait_seconds = 120;
        let check_interval_seconds = 2;
        let start_time = std::time::Instant::now();
        
        loop {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed >= max_wait_seconds {
                eprintln!("   ⏱️  Timeout waiting for relayer confirmation ({}s)", max_wait_seconds);
                eprintln!("   💡 Transaction was submitted but confirmation timed out");
                eprintln!("   💡 Check status at: {}", status_url);
                anyhow::bail!("Relayer transaction confirmation timeout after {} seconds", max_wait_seconds);
            }
            
            // Check transaction status
            match self.client
                .get(&status_url)
                .header("User-Agent", "polymarket-trading-bot/1.0")
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        let status_text = response.text().await
                            .context("Failed to read relayer status response")?;
                        
                        let status_data: serde_json::Value = serde_json::from_str(&status_text)
                            .context("Failed to parse relayer status response")?;
                        
                        let state = status_data["state"].as_str()
                            .unwrap_or("UNKNOWN");
                        
                        match state {
                            "STATE_CONFIRMED" => {
                                let tx_hash = status_data["transactionHash"].as_str()
                                    .unwrap_or("N/A");
                                eprintln!("   ✅ Transaction confirmed! Hash: {}", tx_hash);
                                return Ok(tx_hash.to_string());
                            }
                            "STATE_FAILED" | "STATE_INVALID" => {
                                let error_msg = status_data["metadata"].as_str()
                                    .unwrap_or("Transaction failed");
                                anyhow::bail!("Relayer transaction failed: {}", error_msg);
                            }
                            "STATE_NEW" | "STATE_EXECUTED" | "STATE_MINE" => {
                                eprintln!("   ⏳ Transaction state: {} (elapsed: {}s)", state, elapsed);
                                tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                                continue;
                            }
                            _ => {
                                eprintln!("   ⏳ Transaction state: {} (elapsed: {}s)", state, elapsed);
                                tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                                continue;
                            }
                        }
                    } else {
                        warn!("Failed to check relayer status (status: {}): will retry", response.status());
                        tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                        continue;
                    }
                }
                Err(e) => {
                    warn!("Failed to check relayer status: {} - will retry", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                    continue;
                }
            }
        }
    }

    /// Fallback: Approve individual tokens (ETH Up/Down, BTC Up/Down) with large allowance
    /// This is used when setApprovalForAll fails via relayer
    /// Triggers SDK auto-approval by placing tiny test sell orders for each token
    pub async fn approve_individual_tokens(&self, eth_market_data: &crate::models::Market, btc_market_data: &crate::models::Market) -> Result<()> {
        eprintln!("🔄 Fallback: Approving individual tokens with large allowance...");
        
        // Get token IDs from current markets
        let eth_condition_id = &eth_market_data.condition_id;
        let btc_condition_id = &btc_market_data.condition_id;
        
        let mut token_ids = Vec::new();
        
        // Get ETH market tokens
        if let Ok(eth_details) = self.get_market(eth_condition_id).await {
            for token in &eth_details.tokens {
                token_ids.push((token.token_id.clone(), format!("ETH {}", token.outcome)));
            }
        }
        
        // Get BTC market tokens
        if let Ok(btc_details) = self.get_market(btc_condition_id).await {
            for token in &btc_details.tokens {
                token_ids.push((token.token_id.clone(), format!("BTC {}", token.outcome)));
            }
        }
        
        if token_ids.is_empty() {
            anyhow::bail!("Could not find any token IDs from current markets");
        }
        
        eprintln!("   Found {} tokens to approve", token_ids.len());
        
        // For each token, trigger SDK auto-approval by placing a tiny test sell order
        // The SDK will automatically approve with a large amount (typically max uint256)
        let mut success_count = 0;
        let mut fail_count = 0;
        
        for (token_id, description) in &token_ids {
            eprintln!("   🔐 Checking {} token balance...", description);
            
            // Check if user has balance for this token before attempting approval
            match self.check_balance_allowance(token_id).await {
                Ok((balance, _)) => {
                    let balance_decimal = balance / rust_decimal::Decimal::from(1_000_000u64);
                    let balance_f64 = f64::try_from(balance_decimal).unwrap_or(0.0);
                    
                    if balance_f64 == 0.0 {
                        eprintln!("   ⏭️  Skipping {} token - no balance (balance: 0)", description);
                        continue; // Skip tokens user doesn't own
                    }
                    
                    eprintln!("   ✅ {} token has balance: {:.6} - triggering approval...", description, balance_f64);
                }
                Err(e) => {
                    eprintln!("   ⚠️  Could not check balance for {} token: {} - skipping", description, e);
                    continue; // Skip if we can't check balance
                }
            }
            
            // Place a tiny sell order (0.01 shares) to trigger SDK's auto-approval
            // This order will likely fail due to size, but it will trigger the approval process
            // Using 0.01 (minimum non-zero with 2 decimal places) instead of 0.000001 which rounds to 0.00
            match self.place_market_order(token_id, 0.01, "SELL", Some("FAK")).await {
                Ok(_) => {
                    eprintln!("   ✅ {} token approved successfully", description);
                    success_count += 1;
                }
                Err(e) => {
                    // Check if it's an allowance error (which means approval was triggered)
                    let error_str = format!("{}", e);
                    if error_str.contains("balance") || error_str.contains("allowance") {
                        eprintln!("   ✅ {} token approval triggered (order failed but approval succeeded)", description);
                        success_count += 1;
                    } else {
                        eprintln!("   ⚠️  {} token approval failed: {}", description, error_str);
                        fail_count += 1;
                    }
                }
            }
            
            // Small delay between approvals
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        
        if success_count > 0 {
            eprintln!("✅ Successfully approved {}/{} tokens with large allowance", success_count, token_ids.len());
            if fail_count > 0 {
                eprintln!("   ⚠️  {} tokens failed to approve (will retry on sell if needed)", fail_count);
            }
            Ok(())
        } else {
            anyhow::bail!("Failed to approve any tokens. All {} attempts failed.", token_ids.len())
        }
    }

    /// Place a market order (FOK/FAK) for immediate execution
    /// 
    /// This is used for emergency selling or when you want immediate execution at market price.
    /// Equivalent to JavaScript: client.createAndPostMarketOrder(userMarketOrder)
    /// 
    /// Market orders execute immediately at the best available price:
    /// - FOK (Fill-or-Kill): Order must fill completely or be cancelled
    /// - FAK (Fill-and-Kill): Order fills as much as possible, remainder is cancelled
    pub async fn place_market_order(
        &self,
        token_id: &str,
        amount: f64,
        side: &str,
        order_type: Option<&str>, // "FOK" or "FAK", defaults to FOK
    ) -> Result<OrderResponse> {
        match side {
            "BUY" | "SELL" => {},
            _ => anyhow::bail!("Invalid order side: {}. Must be 'BUY' or 'SELL'", side),
        }
        let order_type_str = order_type.unwrap_or("FOK");

        use rust_decimal::{Decimal, RoundingStrategy};
        use rust_decimal::prelude::*;
        let amount_decimal = if side == "BUY" {
            Decimal::from_f64_retain(amount)
                .ok_or_else(|| anyhow::anyhow!("Failed to convert amount to Decimal"))?
                .round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
        } else {
            let shares_str = format!("{:.2}", amount);
            let d = Decimal::from_str(&shares_str)
                .context(format!("Failed to parse shares '{}' as Decimal", shares_str))?;
            if d <= Decimal::ZERO {
                anyhow::bail!("Invalid shares amount: {}. Must be greater than 0.", d);
            }
            d
        };
        let amount_str = amount_decimal.to_string();
        let amount_is_usdc = side == "BUY";

        if side == "BUY" {
            crate::log_info!("Checking USDC balance and allowance before BUY order");
            if let Ok((usdc_balance, usdc_allowance)) = self.check_usdc_balance_allowance().await {
                let usdc_balance_f64 = f64::try_from(usdc_balance / rust_decimal::Decimal::from(1_000_000u64)).unwrap_or(0.0);
                let usdc_allowance_f64 = f64::try_from(usdc_allowance / rust_decimal::Decimal::from(1_000_000u64)).unwrap_or(0.0);
                crate::log_info!("  USDC balance: ${:.2}, allowance: ${:.2}, order: ${:.2}", usdc_balance_f64, usdc_allowance_f64, amount_decimal);
                if usdc_balance_f64 < f64::try_from(amount_decimal).unwrap_or(0.0) {
                    anyhow::bail!(
                        "Insufficient USDC balance for BUY order. Required: ${:.2}, Available: ${:.2}",
                        amount_decimal, usdc_balance_f64
                    );
                }
                if usdc_allowance_f64 < f64::try_from(amount_decimal).unwrap_or(0.0) {
                    crate::log_warn!("  USDC allowance (${:.2}) < order amount (${:.2})", usdc_allowance_f64, amount_decimal);
                }
            } else {
                crate::log_warn!("  Could not check USDC balance/allowance (continuing anyway)");
            }
        }

        crate::log_action!("Placing market order: {} {} {} (type: {})", side, amount_str, token_id, order_type_str);

        let handle = self.get_client_handle().await?;
        let token_id_owned = token_id.to_string();
        let side_owned = side.to_string();
        let mut retry = 0;
        let max_retries = if side == "SELL" { 3 } else { 1 };

        let order_id = loop {
            let tid = token_id_owned.clone();
            let sid = side_owned.clone();
            let amt = amount_str.clone();
            let ot = order_type_str.to_string();
            let res = tokio::task::spawn_blocking(move || {
                clob_sdk_ffi::post_market_order(handle, &tid, &sid, &amt, amount_is_usdc, &ot)
            })
            .await
            .context("place_market_order spawn_blocking");
            match res {
                Ok(Ok(id)) => break id,
                Ok(Err(e)) => {
                    let err_str = e.to_string();
                    retry += 1;
                    crate::log_error!("Market order failed (attempt {}/{}): {}", retry, max_retries, err_str);
                    let is_allowance = err_str.to_lowercase().contains("allowance");
                    let is_balance = err_str.to_lowercase().contains("balance") && !is_allowance;
                    if is_balance {
                        anyhow::bail!("Insufficient token balance: {}", err_str);
                    }
                    if is_allowance && side == "SELL" && retry < max_retries {
                        if let Err(refresh_err) = self.update_balance_allowance_for_sell(token_id).await {
                            crate::log_warn!("  Refresh allowance cache failed: {} (retrying anyway)", refresh_err);
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        continue;
                    }
                    if is_allowance {
                        anyhow::bail!("Allowance error: {}", err_str);
                    }
                    anyhow::bail!("Failed to post market order: {}", err_str);
                }
                Err(e) => anyhow::bail!("spawn_blocking: {}", e),
            }
        };

        crate::log_ok!("Market order executed. Order ID: {}", order_id);
        Ok(OrderResponse {
            order_id: Some(order_id.clone()),
            status: "LIVE".to_string(),
            message: Some(format!("Market order executed. Order ID: {}", order_id)),
        })
    }
    
    /// Place an order using REST API with HMAC authentication (fallback method)
    /// 
    /// NOTE: This is a fallback method. The main place_order() method uses the official SDK
    /// with proper private key signing. Use this only if SDK integration fails.
    #[allow(dead_code)]
    async fn place_order_hmac(&self, order: &OrderRequest) -> Result<OrderResponse> {
        let path = "/orders";
        let url = format!("{}{}", self.clob_url, path);
        
        // Serialize order to JSON string for signature
        let body = serde_json::to_string(order)
            .context("Failed to serialize order to JSON")?;
        
        let mut request = self.client.post(&url).json(order);
        
        // Add HMAC-SHA256 authentication headers (L2 authentication)
        request = self.add_auth_headers(request, "POST", path, &body)
            .context("Failed to add authentication headers")?;

        eprintln!("📤 Posting order to Polymarket (HMAC): {} {} {} @ {}", 
              order.side, order.size, order.token_id, order.price);

        let response = request
            .send()
            .await
            .context("Failed to place order")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            
            // Provide helpful error messages
            if status == 401 || status == 403 {
                anyhow::bail!(
                    "Authentication failed (status: {}): {}",
                    status, error_text
                );
            }
            
            anyhow::bail!("Failed to place order (status: {}): {}", status, error_text);
        }

        let order_response: OrderResponse = response
            .json()
            .await
            .context("Failed to parse order response")?;

        eprintln!("✅ Order placed successfully: {:?}", order_response);
        Ok(order_response)
    }

    /// Redeem winning conditional tokens after market resolution
    /// 
    /// This uses the CTF (Conditional Token Framework) contract to redeem winning tokens
    /// for USDC at 1:1 ratio after market resolution.
    /// 
    /// Parameters:
    /// - condition_id: The condition ID of the resolved market
    /// - token_id: The token ID of the winning token (for logging; can be "" when redeeming by condition_id)
    /// - outcome: "Up", "Down", or description (for logging)
    /// - redeem_yes: Include YES (index set 1) in redemption
    /// - redeem_no: Include NO (index set 2) in redemption. Contract only pays out winning side.
    /// 
    /// Reference: Polymarket CTF redemption (same as Python redeem_positions).
    /// USDC collateral: 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174
    pub async fn redeem_tokens(
        &self,
        condition_id: &str,
        token_id: &str,
        outcome: &str,
        redeem_yes: bool,
        redeem_no: bool,
    ) -> Result<RedeemResponse> {
        // Using Relayer Client for gasless transactions (same as Python RelayClient)
        // Based on docs: https://docs.polymarket.com/developers/builders/relayer-client#redeem-positions
        
        // USDC collateral token address on Polygon
        let collateral_token = AlloyAddress::parse_checksummed(
            "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
            None
        ).context("Failed to parse USDC address")?;
        
        // Parse condition_id to B256 (remove 0x prefix if present)
        let condition_id_clean = condition_id.strip_prefix("0x").unwrap_or(condition_id);
        let condition_id_b256 = B256::from_str(condition_id_clean)
            .context(format!("Failed to parse condition_id to B256: {}", condition_id))?;
        
        // Index sets: YES = 1 (binary index 0), NO = 2 (binary index 1). Same as Python BINARY_YES_INDEX_SET/BINARY_NO_INDEX_SET.
        let mut index_sets = Vec::new();
        if redeem_yes {
            index_sets.push(U256::from(1));
        }
        if redeem_no {
            index_sets.push(U256::from(2));
        }
        if index_sets.is_empty() {
            anyhow::bail!("Must redeem at least one position (YES or NO). Use redeem_yes and/or redeem_no.");
        }
        
        eprintln!("🔄 Redeeming tokens for condition {} (outcome: {})", condition_id, outcome);
        eprintln!("   📋 Index sets: {:?} (contract will only redeem winning tokens)", index_sets);
        
        // Use Relayer Client for gasless transactions. The /execute path returns 404;
        // builder-relayer-client uses POST /submit. See: Polymarket/builder-relayer-client
        // CTF contract: 0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E
        // Function: redeemPositions(address collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] indexSets)
        
        const CTF_CONTRACT: &str = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E";
        const RELAYER_SUBMIT: &str = "https://relayer-v2.polymarket.com/submit";
        
        let relayer_url = RELAYER_SUBMIT;
        
        // Parse CTF contract address using AlloyAddress
        // Use parse instead of parse_checksummed to avoid checksum validation issues
        eprintln!("   🔍 Parsing CTF contract address: {}", CTF_CONTRACT);
        let ctf_address = CTF_CONTRACT.strip_prefix("0x")
            .and_then(|s| {
                eprintln!("   🔍 Decoding hex: {}", s);
                hex::decode(s).ok()
            })
            .and_then(|bytes| {
                eprintln!("   🔍 Decoded bytes length: {}", bytes.len());
                if bytes.len() == 20 {
                    Some(AlloyAddress::from_slice(&bytes))
                } else {
                    eprintln!("   ⚠️  Invalid address length: {} (expected 20)", bytes.len());
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("Invalid CTF contract address format: {}", CTF_CONTRACT))
            .context("Failed to parse CTF contract address")?;
        eprintln!("   ✅ Successfully parsed CTF address: {:#x}", ctf_address);
        
        let parent_collection_id = B256::ZERO;
        
        eprintln!("   Prepared redemption parameters:");
        eprintln!("   - CTF Contract: {}", ctf_address);
        eprintln!("   - Collateral token (USDC): {}", collateral_token);
        eprintln!("   - Condition ID: {} ({:?})", condition_id, condition_id_b256);
        eprintln!("   - Index sets: {:?} (contract will only redeem winning tokens)", index_sets);
        eprintln!("   - Outcome: {}", outcome);
        
        // Encode the redeemPositions function call
        // Function signature: redeemPositions(address,bytes32,bytes32,uint256[])
        // Function selector: keccak256("redeemPositions(address,bytes32,bytes32,uint256[])")[0:4] = 0x3d7d3f5a
        
        // Function selector
        let function_selector = hex::decode("3d7d3f5a")
            .context("Failed to decode function selector")?;
        
        // Encode parameters manually using ABI encoding rules
        // Parameters: (address, bytes32, bytes32, uint256[])
        let mut encoded_params = Vec::new();
        
        // Encode address (20 bytes, left-padded to 32 bytes)
        let mut addr_bytes = [0u8; 32];
        addr_bytes[12..].copy_from_slice(collateral_token.as_slice());
        encoded_params.extend_from_slice(&addr_bytes);
        
        // Encode parentCollectionId (bytes32)
        encoded_params.extend_from_slice(parent_collection_id.as_slice());
        
        // Encode conditionId (bytes32)
        encoded_params.extend_from_slice(condition_id_b256.as_slice());
        
        // Encode indexSets array: offset (32 bytes) + length (32 bytes) + data (32 bytes per element)
        // Offset points to where array data starts (after all fixed params + offset itself)
        // Fixed params: address (32) + bytes32 (32) + bytes32 (32) + offset (32) = 128 bytes
        let array_offset = 32 * 4; // offset to array data (3 fixed params + 1 offset param)
        let array_length = index_sets.len();
        
        // Offset to array data (32 bytes)
        let offset_bytes = U256::from(array_offset).to_be_bytes::<32>();
        encoded_params.extend_from_slice(&offset_bytes);
        
        // Now append array data after all fixed parameters
        // Array length (32 bytes)
        let length_bytes = U256::from(array_length).to_be_bytes::<32>();
        encoded_params.extend_from_slice(&length_bytes);
        
        // Array data (each uint256 is 32 bytes)
        for idx in &index_sets {
            let idx_bytes = idx.to_be_bytes::<32>();
            encoded_params.extend_from_slice(&idx_bytes);
        }
        
        // Combine function selector with encoded parameters
        let mut call_data = function_selector;
        call_data.extend_from_slice(&encoded_params);
        let call_data_hex = format!("0x{}", hex::encode(&call_data));
        
        eprintln!("   Using Relayer Client for gasless redemption...");
        eprintln!("   Relayer URL: {}", relayer_url);
        
        // Build transaction for relayer
        // Relayer expects: { transactions: [{ to, data, value }], description }
        let ctf_address_str = format!("{:#x}", ctf_address);
        let transaction = serde_json::json!({
            "to": ctf_address_str,
            "data": call_data_hex,
            "value": "0"
        });
        
        let relayer_request = serde_json::json!({
            "transactions": [transaction],
            "description": format!("Redeem {} token for condition {}", outcome, condition_id)
        });
        
        // Add authentication headers (Builder API credentials)
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API key required for relayer. Please set api_key in config.json"))?;
        let api_secret = self.api_secret.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API secret required for relayer. Please set api_secret in config.json"))?;
        let api_passphrase = self.api_passphrase.as_ref()
            .ok_or_else(|| anyhow::anyhow!("API passphrase required for relayer. Please set api_passphrase in config.json"))?;
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        
        let body_string = serde_json::to_string(&relayer_request)
            .context("Failed to serialize relayer request")?;
        
        // Generate HMAC signature for relayer authentication
        // Message format: POST + /submit + body + timestamp
        // This must match exactly what the relayer expects
        let url_path = "/submit";
        let message = format!("POST{}{}{}", url_path, body_string, timestamp);
        
        // Try to decode secret from base64url first (Builder API uses base64url encoding)
        // Base64url uses - and _ instead of + and /, making it URL-safe
        // Then try standard base64, then fall back to raw bytes
        let secret_bytes = {
            use base64::engine::general_purpose;
            use base64::Engine;
            
            // First try base64url (URL_SAFE engine)
            if let Ok(bytes) = general_purpose::URL_SAFE.decode(api_secret) {
                bytes
            }
            // Then try standard base64
            else if let Ok(bytes) = general_purpose::STANDARD.decode(api_secret) {
                bytes
            }
            // Finally, use raw bytes if both fail
            else {
                api_secret.as_bytes().to_vec()
            }
        };
        
        let mut mac = HmacSha256::new_from_slice(&secret_bytes)
            .context("Failed to create HMAC from API secret")?;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());
        
        // Send request to relayer
        // CRITICAL: Use .body() with the exact same body_string used for HMAC
        // This ensures the request body matches exactly what was signed
        let response = self.client
            .post(relayer_url)
            .header("User-Agent", "polymarket-trading-bot/1.0")
            .header("POLY_BUILDER_API_KEY", api_key)
            .header("POLY_BUILDER_TIMESTAMP", &timestamp)
            .header("POLY_BUILDER_PASSPHRASE", api_passphrase)
            .header("POLY_BUILDER_SIGNATURE", &signature)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body_string)  // Use the exact same body string used for HMAC
            .send()
            .await
            .context("Failed to send redemption request to relayer")?;
        
        let status = response.status();
        let response_text = response.text().await
            .context("Failed to read relayer response")?;
        
        eprintln!("   📥 Relayer response status: {}", status);
        eprintln!("   📥 Relayer response: {}", &response_text[..500.min(response_text.len())]);
        
        if !status.is_success() {
            // Provide detailed error message for 401 Unauthorized
            if status == 401 {
                anyhow::bail!(
                    "Relayer redemption failed: 401 Unauthorized - Invalid Builder API credentials\n\
                    \n\
                    This error means your Builder API credentials are incorrect or missing.\n\
                    \n\
                    Please verify:\n\
                    1. You're using Builder API credentials (not User API credentials)\n\
                    2. Get Builder API credentials from: https://polymarket.com/builder\n\
                    3. Your config.json has:\n\
                       - api_key: Your Builder API key\n\
                       - api_secret: Your Builder API secret (base64-encoded)\n\
                       - api_passphrase: Your Builder API passphrase\n\
                    4. The credentials match your Builder Profile exactly\n\
                    5. Your Builder API credentials were derived with the correct signature_type ({})\n\
                    \n\
                    Response: {}",
                    self.signature_type.unwrap_or(0),
                    &response_text[..500.min(response_text.len())]
                );
            }
            
            anyhow::bail!(
                "Relayer redemption failed (status {}): {}",
                status, &response_text[..200.min(response_text.len())]
            );
        }
        
        // Parse relayer response
        let relayer_response: serde_json::Value = serde_json::from_str(&response_text)
            .context("Failed to parse relayer response")?;
        
        let transaction_id = relayer_response["transactionID"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing transactionID in relayer response"))?;
        
        eprintln!("   ✅ Relayer transaction submitted successfully");
        eprintln!("   Transaction ID: {}", transaction_id);
        eprintln!("   Waiting for transaction confirmation...");
        
        // Poll for transaction status
        // Relayer states: STATE_NEW, STATE_EXECUTED, STATE_MINE, STATE_CONFIRMED, STATE_FAILED, STATE_INVALID
        let status_url = format!("https://relayer-v2.polymarket.com/transaction/{}", transaction_id);
        
        // Poll for transaction confirmation (with timeout)
        let max_wait_seconds = 120;
        let check_interval_seconds = 2;
        let start_time = std::time::Instant::now();
        
        loop {
            let elapsed = start_time.elapsed().as_secs();
            if elapsed >= max_wait_seconds {
                eprintln!("   ⏱️  Timeout waiting for relayer confirmation ({}s) - will retry on next check", max_wait_seconds);
                return Ok(RedeemResponse {
                    success: false,
                    message: Some(format!("Relayer transaction submitted (ID: {}), but confirmation timeout. Will retry.", transaction_id)),
                    transaction_hash: Some(transaction_id.to_string()),
                    amount_redeemed: None,
                });
            }
            
            // Generate new timestamp and signature for status check
            let status_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string();
            
            let status_message = format!("GET{}{}", status_url, status_timestamp);
            
            // Try to decode secret from base64url first (Builder API uses base64url encoding)
            // Base64url uses - and _ instead of + and /, making it URL-safe
            // Then try standard base64, then fall back to raw bytes
            let status_secret_bytes = {
                use base64::engine::general_purpose;
                use base64::Engine;
                
                // First try base64url (URL_SAFE engine)
                if let Ok(bytes) = general_purpose::URL_SAFE.decode(api_secret) {
                    bytes
                }
                // Then try standard base64
                else if let Ok(bytes) = general_purpose::STANDARD.decode(api_secret) {
                    bytes
                }
                // Finally, use raw bytes if both fail
                else {
                    api_secret.as_bytes().to_vec()
                }
            };
            
            let mut status_mac = HmacSha256::new_from_slice(&status_secret_bytes)
                .context("Failed to create HMAC for status check")?;
            status_mac.update(status_message.as_bytes());
            let status_signature = hex::encode(status_mac.finalize().into_bytes());
            
            // Check transaction status
            match self.client
                .get(&status_url)
                .header("POLY_BUILDER_API_KEY", api_key)
                .header("POLY_BUILDER_TIMESTAMP", &status_timestamp)
                .header("POLY_BUILDER_PASSPHRASE", api_passphrase)
                .header("POLY_BUILDER_SIGNATURE", &status_signature)
                .send()
                .await
            {
                Ok(status_response) => {
                    if status_response.status().is_success() {
                        match status_response.json::<serde_json::Value>().await {
                            Ok(status_data) => {
                                let state = status_data["state"].as_str()
                                    .unwrap_or("UNKNOWN");
                                let tx_hash = status_data["transactionHash"].as_str();
                                
                                eprintln!("   Transaction state: {} (elapsed: {}s)", state, elapsed);
                                
                                match state {
                                    "STATE_CONFIRMED" => {
                                        let redeem_response = RedeemResponse {
                                            success: true,
                                            message: Some(format!("Successfully redeemed tokens via relayer. Transaction ID: {}", transaction_id)),
                                            transaction_hash: tx_hash.map(|s| s.to_string()),
                                            amount_redeemed: None,
                                        };
                                        
                                        eprintln!("✅ Successfully redeemed tokens via Relayer Client!");
                                        eprintln!("   Transaction ID: {}", transaction_id);
                                        if let Some(hash) = tx_hash {
                                            eprintln!("   Transaction hash: {}", hash);
                                        }
                                        
                                        return Ok(redeem_response);
                                    }
                                    "STATE_FAILED" | "STATE_INVALID" => {
                                        anyhow::bail!(
                                            "Relayer redemption transaction failed (state: {}). Transaction ID: {}",
                                            state, transaction_id
                                        );
                                    }
                                    _ => {
                                        // STATE_NEW, STATE_EXECUTED, STATE_MINE - still processing
                                        tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse status response: {} - will retry", e);
                                tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                                continue;
                            }
                        }
                    } else {
                        // Status check failed, wait and retry
                        tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                        continue;
                    }
                }
                Err(e) => {
                    warn!("Failed to check relayer status: {} - will retry", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(check_interval_seconds)).await;
                    continue;
                }
            }
        }
    }

    /// Merge complete sets of Up and Down tokens for a condition into USDC.
    /// Burns min(Up_balance, Down_balance) pairs and returns that much USDC via the CTF relayer.
    /// Uses the same redeemPositions(conditionId, [1,2]) flow as redeem_tokens.
    pub async fn merge_complete_sets(&self, condition_id: &str) -> Result<RedeemResponse> {
        self.redeem_tokens(condition_id, "", "Up+Down (merge complete sets)", true, true).await
    }
}

