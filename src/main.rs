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
    pub fn src(mut self, ip: IpAddr) -> Self { self.src = ip; self }
    pub fn dst(mut self, ip: IpAddr) -> Self { self.dst = ip; self }
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

    pub fn src(mut self, ip: IpAddr) -> Self {
        self.src = Some(ip);
        self
    }

    pub fn dst(mut self, ip: IpAddr) -> Self {
        self.dst = Some(ip);
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

    ///---- Rules Tests ---///
    #[test]
    fn rule_matches_on_protocol() {
        let rule = Rule::new().protocol(Protocol::Udp);
        let packet = Packet::builder().protocol(Protocol::Udp).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_protocol_differs() {
        let rule = Rule::new().protocol(Protocol::Tcp);
        let packet = Packet::builder().protocol(Protocol::Udp).build();

        assert_eq!(rule.matches(&packet), false);
    }

    #[test]
    fn rule_matches_on_src() {
        let rule = Rule::new().src("10.0.0.1".parse().unwrap());
        let packet = Packet::builder().src("10.0.0.1".parse().unwrap()).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_src_differs() {
        let rule = Rule::new().src("10.0.0.1".parse().unwrap());
        let packet = Packet::builder().src("10.0.0.3".parse().unwrap()).build();

        assert_eq!(rule.matches(&packet), false);
    }

    #[test]
    fn rule_matches_on_dst() {
        let rule = Rule::new().dst("10.0.0.4".parse().unwrap());
        let packet = Packet::builder().dst("10.0.0.4".parse().unwrap()).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_dst_differs() {
        let rule = Rule::new().dst("10.0.0.4".parse().unwrap());
        let packet = Packet::builder().dst("10.0.0.1".parse().unwrap()).build();

        assert_eq!(rule.matches(&packet), false);
    }

    #[test]
    fn rule_matches_on_sport() {
        let rule = Rule::new().sport(22);
        let packet = Packet::builder().sport(22).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_sport_differs() {
        let rule = Rule::new().sport(143);
        let packet = Packet::builder().sport(103).build();

        assert_eq!(rule.matches(&packet), false);
    }

    #[test]
    fn rule_matches_on_dport() {
        let rule = Rule::new().dport(22);
        let packet = Packet::builder().dport(22).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_dport_differs() {
        let rule = Rule::new().dport(143);
        let packet = Packet::builder().dport(103).build();
        
        assert_eq!(rule.matches(&packet), false);
    }

    #[test]
    fn rule_matches_when_all_criteria_match_together() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1".parse().unwrap()).dst("10.2.5.4".parse().unwrap()).dport(22);
        let packet = Packet::builder().protocol(Protocol::Tcp).src("10.0.0.1".parse().unwrap()).dst("10.2.5.4".parse().unwrap()).dport(22).build();

        assert_eq!(rule.matches(&packet), true);
    }

    #[test]
    fn rule_does_not_match_when_one_criterion_among_several_differs() {
        let rule = Rule::new().protocol(Protocol::Tcp).src("10.0.0.1".parse().unwrap()).dst("10.2.5.4".parse().unwrap()).dport(80);
        let packet = Packet::builder().protocol(Protocol::Udp).src("10.0.0.1".parse().unwrap()).dst("10.2.6.4".parse().unwrap()).dport(2222).build();

        assert_eq!(rule.matches(&packet), false);
    }


    ///---- Rule Engine Tests ---///
    #[test]
    fn no_rules_means_packet_is_denied_by_default() {
        let engine = RuleEngine::new(vec![]);
        let packet = Packet::builder().build();

        assert_eq!(engine.decide(&packet), Action::Deny);
    }

    #[test]
    fn rule_without_ip_matches_any_source_and_destination() {
        let rule = Rule::new().protocol(Protocol::Tcp).dport(22).action(Action::Allow);
        let engine = RuleEngine::new(vec![rule]);

        let packet1 = Packet::builder().src("10.0.0.15".parse().unwrap()).dst("10.0.0.26".parse().unwrap()).dport(22).build();
        let packet2 = Packet::builder().src("192.168.1.1".parse().unwrap()).dst("8.8.8.8".parse().unwrap()).dport(22).build();

        assert_eq!(engine.decide(&packet1), Action::Allow);
        assert_eq!(engine.decide(&packet2), Action::Allow);
    }

    #[test]
    fn first_matching_rule_wins() {
        let rule1 = Rule::new().dport(22).action(Action::Allow);
        let rule2 = Rule::new().dport(22).action(Action::Deny);
        let engine = RuleEngine::new(vec![rule1, rule2]);
        let packet = Packet::builder().dport(22).build();

        assert_eq!(engine.decide(&packet), Action::Allow);
    }
}