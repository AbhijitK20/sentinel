use sha2::{Digest, Sha256};

pub struct AstResult {
    pub source_hash: String,
    pub total_lines: usize,
}

pub fn parse_source(source: &str) -> AstResult {
    let source_hash = compute_hash(source);
    let total_lines = source.lines().count();

    AstResult {
        source_hash,
        total_lines,
    }
}

pub fn compute_hash(source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn compute_file_hash(path: &std::path::Path) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Some(format!("{:x}", hasher.finalize()))
}
