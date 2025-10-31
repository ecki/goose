use crate::providers::gondola::GondolaProvider;
use anyhow::{Context, Result};

pub struct MlDetector {
    provider: GondolaProvider,
    config: ModelConfig,
}

pub struct ModelConfig {
    pub model: String,
    pub version: String,
    pub input_name: String,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model: "deberta-prompt-injection-v2".to_string(),
            version: "gmv-zve9abhxe9s7fq1zep5dxd807".to_string(),
            input_name: "text_input".to_string(),
        }
    }
}

impl MlDetector {
    pub fn new(provider: GondolaProvider, config: ModelConfig) -> Self {
        Self { provider, config }
    }

    pub fn from_env() -> Result<Self> {
        let provider = GondolaProvider::from_env()
            .context("Failed to initialize Gondola provider for ML detection")?;
        
        let config = ModelConfig::default();
        Ok(Self::new(provider, config))
    }

    pub async fn scan(&self, text: &str) -> Result<f32> {
        tracing::debug!(
            text_length = text.len(),
            text_preview = %text.chars().take(100).collect::<String>(),
            "ML detection scanning text"
        );

        let response = self
            .provider
            .batch_infer(
                &self.config.model,
                &self.config.version,
                &self.config.input_name,
                &[text.to_string()],
            )
            .await
            .context("ML inference failed")?;

        let item = response
            .response_items
            .first()
            .context("No response items from ML model")?;

        let logits = item
            .double_list_value
            .as_ref()
            .context("No logits in response")?
            .double_values
            .as_slice();

        if logits.len() < 2 {
            anyhow::bail!("Expected 2 logits (safe, malicious), got {}", logits.len());
        }

        let exp_safe = logits[0].exp();
        let exp_malicious = logits[1].exp();
        let sum = exp_safe + exp_malicious;
        let confidence = (exp_malicious / sum) as f32;

        tracing::info!(
            logit_safe = %logits[0],
            logit_malicious = %logits[1],
            prob_safe = %(exp_safe / sum),
            prob_malicious = %(exp_malicious / sum),
            confidence = %confidence,
            "ML detection raw results"
        );

        Ok(confidence)
    }
}
