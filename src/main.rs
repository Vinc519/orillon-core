use std::net::IpAddr;

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
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

pub struct PacketBuilder {
    protocol: Protocol,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
}

impl Packet {
    pub fn builder() -> PacketBuilder {
        PacketBuilder {
            protocol: Protocol::Tcp,
            src: "0.0.0.0".parse().unwrap(),
            dst: "0.0.0.0".parse().unwrap(),
            sport: 0,
            dport: 0,
        }
    }
}

impl PacketBuilder {
    pub fn protocol(mut self, p: Protocol) -> Self { self.protocol = p; self }
    pub fn src(mut self, ip: &str) -> Self { self.src = ip.parse().unwrap(); self }
    pub fn dst(mut self, ip: &str) -> Self { self.dst = ip.parse().unwrap(); self }
    pub fn sport(mut self, port: u16) -> Self { self.sport = port; self }
    pub fn dport(mut self, port: u16) -> Self { self.dport = port; self }

    pub fn build(self) -> Packet {
        Packet {
            protocol: self.protocol, 
            src: self.src,
            dst: self.dst,
            sport: self.sport,
            dport: self.dport,
        }
    }
}

pub struct Rule {
    protocol: Option<Protocol>,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
    action: Action,
}

impl Rule {
    pub fn new() -> Self {
        Self {
            protocol: None,
            src: None,
            dst: None,
            sport: None,
            dport: None,
            action: Action::Deny,
        }
    }

    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn src(mut self, ip: &str) -> Self {
        self.src = Some(ip.parse().unwrap());
        self
    }

    pub fn dst(mut self, ip: &str) -> Self {
        self.dst = Some(ip.parse().unwrap());
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
        self.action = action;
        self
    }

    pub fn matches(&self, packet: &Packet) -> bool {
        self.protocol.is_none_or(|p| p == packet.protocol)
            && self.src.is_none_or(|src| src == packet.src)
            && self.dst.is_none_or(|dst| dst == packet.dst)
            && self.sport.is_none_or(|sport| sport == packet.sport)
            && self.dport.is_none_or(|dport| dport == packet.dport)
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
        self.rules
            .iter()
            .find(|rule| rule.matches(packet))
            .map(|rule| rule.action)
            .unwrap_or(Action::Deny)
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
        let packet = Packet::builder().build();
        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn matching_rule_action_is_applied() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.1").build();

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn non_matching_rule_falls_back_to_default() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.3").build();

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn destination_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").dst("10.0.0.4").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.1").dst("10.0.0.4").build();

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn destination_non_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1").dst("10.0.0.4").action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.4").dst("10.0.0.1").build();

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn sport_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.15").dst("10.0.0.26").sport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.15").dst("10.0.0.26").sport(22).build();

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn sport_non_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.55").dst("10.0.0.43").sport(143).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.55").dst("10.0.0.43").sport(103).build();

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn dport_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.15").dst("10.0.0.26").dport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.15").dst("10.0.0.26").dport(22).build();

        assert_eq!(engine.decide(&packet), Action::Allow);
    }

    #[test]
    fn dport_non_matching() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.55").dst("10.0.0.43").dport(143).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.55").dst("10.0.0.43").dport(103).build();
        
        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn without_ip_matches_any_source_and_destination() {
        let rule = Rule::new().protocol(Protocol::Tcp).dport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);

        let packet1 = Packet::builder().src("10.0.0.15").dst("10.0.0.26").dport(22).build();
        let packet2 = Packet::builder().src("192.168.1.1").dst("8.8.8.8").dport(22).build();

        assert_eq!(engine.decide(&packet1), Action::Allow);
        assert_eq!(engine.decide(&packet2), Action::Allow);
    }

    #[test]
    fn without_ip_non_matching_on_port() {
        let rule = Rule::new().protocol(Protocol::Tcp).dport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);
        let packet = Packet::builder().src("10.0.0.159").dst("10.0.0.76").dport(103).build();
        
        assert_eq!(engine.decide(&packet), Action::Deny);
    }
}