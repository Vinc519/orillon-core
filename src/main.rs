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
    sport: u16,
    dport: u16,
}

impl Packet {
    pub fn tcp(src: &str, dst: &str, sport: u16, dport: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            src: src.to_string(),
            dst: dst.to_string(),
            sport: sport,
            dport: dport,
        }
    }
}

pub struct Rule {
    protocol: Option<Protocol>,
    src: Option<String>,
    dst: Option<String>,
    sport: Option<u16>,
    dport: Option<u16>,
    action: Option<Action>,
}

impl Rule {
    pub fn new() -> Self {
        Self {
            protocol: None,
            src: None,
            dst: None,
            sport: None,
            dport: None,
            action: None,
        }
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn src(mut self, src: &str) -> Self {
        self.src = Some(src.to_string());
        self
    }

    pub fn dst(mut self, dst: &str) -> Self {
        self.dst = Some(dst.to_string());
        self
    }

    pub fn sport(mut self, sport: u16) -> Self {
        self.sport = Some(sport);
        self
    }

    pub fn dport(mut self, dport: u16) -> Self {
        self.dport = Some(dport);
        self
    }

    pub fn action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn decide(&self, packet: &Packet) -> Action {
        for rule in &self.rules {
            if rule.protocol.is_none_or(|protocol| protocol == packet.protocol)
            && rule.src.as_deref().is_none_or(|src| src == packet.src)
            && rule.dst.as_deref().is_none_or(|dst| dst == packet.dst)
            && rule.sport.is_none_or(|sport| sport == packet.sport)
            && rule.dport.is_none_or(|dport| dport == packet.dport) {
                return rule.action.unwrap_or(Action::Deny);
            }
        }
        
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
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.1", "10.0.0.2", 1028);

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn non_matching_rule_falls_back_to_default() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.3", "10.0.0.2", 22);

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn destination_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").dst("10.0.0.4").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.1", "10.0.0.4", 25);

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn destination_non_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").dst("10.0.0.4").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.4", "10.0.0.1", 53);

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn sport_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.15").dst("10.0.0.26").sport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.15", "10.0.0.26", 22);

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn sport_non_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.55").dst("10.0.0.43").sport(143).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::tcp("10.0.0.55", "10.0.0.43", 443);

        assert_eq!(engine.decide(&packet), Action::Deny);
    }
}