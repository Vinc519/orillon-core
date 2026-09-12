#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

pub struct Packet {
    protocol: Protocol,
    src: String,
    dst: String,
    port: u16,
}

impl Packet {
    pub fn tcp(src: &str, dst: &str, port: u16) -> Self {
        Self {}
    }
}

pub struct Rule {

}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn decide(&self, packet: &Packet) -> Action {
        Action::Deny
    }
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_rules_means_packet_is_denied_by_default() {
        let engine = RuleEngine::new(vec![]);
        let packet = Packet::tcp("10.0.0.1", "10.0.0.2", 443);
        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn matching_rule_action_is_applied() {
        let rule = Rule::new().src("10.0.0.1").action(Action::Allow);
        let engine = RuleEngine::new(vec![]);
        let packet = Packet::tcp("10.0.0.1", "10.0.0.2", 443);

        assert_eq!(engine.decide(&packet), Action::Allow);
    }
}