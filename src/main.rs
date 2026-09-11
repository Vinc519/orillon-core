fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule() {
        let engine = RuleEngine::new(vec![]);
        let packet = Packet::tcp("10.0.0.1", "10.0.0.2", 443);
        assert_eq!(engine.decide(&packet), Action::Allow);
    }
}