use std::collections::HashMap;

/// Calculate the Shannon entropy of a string (in bits per character).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts = HashMap::new();
    let len = s.chars().count() as f64;

    for c in s.chars() {
        *counts.entry(c).or_insert(0.0) += 1.0;
    }

    counts
        .values()
        .map(|&count| {
            let p = count / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_repeated_char() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn test_entropy_random_looking_string() {
        let entropy = shannon_entropy("8f9b2a7c4e1d603b5a8f");
        assert!(entropy > 3.5, "High density hex token should have high entropy: {}", entropy);
    }
}
