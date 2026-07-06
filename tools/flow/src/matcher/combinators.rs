use crate::{Matcher, PacketContext};

/// Matcher that requires all child matchers to match.
pub struct And {
    matchers: Vec<Box<dyn Matcher>>,
}

impl And {
    /// Create an `And` matcher from boxed child matchers.
    pub fn new(matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self { matchers }
    }
}

impl Matcher for And {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        self.matchers
            .iter()
            .all(|matcher| matcher.matches(packet, ctx))
    }

    fn describe(&self) -> String {
        describe_many("all", " AND ", &self.matchers)
    }
}

/// Matcher that requires any child matcher to match.
pub struct Or {
    matchers: Vec<Box<dyn Matcher>>,
}

impl Or {
    /// Create an `Or` matcher from boxed child matchers.
    pub fn new(matchers: Vec<Box<dyn Matcher>>) -> Self {
        Self { matchers }
    }
}

impl Matcher for Or {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        self.matchers
            .iter()
            .any(|matcher| matcher.matches(packet, ctx))
    }

    fn describe(&self) -> String {
        describe_many("any", " OR ", &self.matchers)
    }
}

/// Matcher that inverts a child matcher.
pub struct Not {
    matcher: Box<dyn Matcher>,
}

impl Not {
    /// Create a `Not` matcher from a boxed child matcher.
    pub fn new(matcher: Box<dyn Matcher>) -> Self {
        Self { matcher }
    }
}

impl Matcher for Not {
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        !self.matcher.matches(packet, ctx)
    }

    fn describe(&self) -> String {
        format!("not({})", self.matcher.describe())
    }
}

/// Convenience methods for composing matcher values.
pub trait MatcherExt: Matcher + Sized + 'static {
    /// Box this matcher as a trait object.
    fn boxed(self) -> Box<dyn Matcher> {
        Box::new(self)
    }

    /// Match when both this matcher and `other` match.
    fn and<M>(self, other: M) -> And
    where
        M: Matcher + 'static,
    {
        let left: Box<dyn Matcher> = Box::new(self);
        let right: Box<dyn Matcher> = Box::new(other);

        And::new(vec![left, right])
    }

    /// Match when either this matcher or `other` matches.
    fn or<M>(self, other: M) -> Or
    where
        M: Matcher + 'static,
    {
        let left: Box<dyn Matcher> = Box::new(self);
        let right: Box<dyn Matcher> = Box::new(other);

        Or::new(vec![left, right])
    }

    /// Match when this matcher does not match.
    fn not(self) -> Not {
        let matcher: Box<dyn Matcher> = Box::new(self);

        Not::new(matcher)
    }
}

impl<T> MatcherExt for T where T: Matcher + Sized + 'static {}

impl<T> Matcher for Box<T>
where
    T: Matcher + ?Sized,
{
    fn matches(&self, packet: &crafter::Packet, ctx: &PacketContext) -> bool {
        (**self).matches(packet, ctx)
    }

    fn describe(&self) -> String {
        (**self).describe()
    }
}

/// Create an `And` matcher from boxed child matchers.
pub fn all(matchers: Vec<Box<dyn Matcher>>) -> And {
    And::new(matchers)
}

/// Create an `Or` matcher from boxed child matchers.
pub fn any(matchers: Vec<Box<dyn Matcher>>) -> Or {
    Or::new(matchers)
}

/// Create a `Not` matcher from a boxed child matcher.
pub fn not(matcher: Box<dyn Matcher>) -> Not {
    Not::new(matcher)
}

fn describe_many(label: &str, separator: &str, matchers: &[Box<dyn Matcher>]) -> String {
    if matchers.is_empty() {
        return format!("{label}()");
    }

    let descriptions = matchers
        .iter()
        .map(|matcher| matcher.describe())
        .collect::<Vec<_>>()
        .join(separator);

    format!("{label}({descriptions})")
}

#[cfg(test)]
mod tests {
    use super::{all, any, not, MatcherExt};
    use crate::{Matcher, PacketContext, PredicateMatcher};

    fn packet() -> crafter::Packet {
        crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef]).expect("raw packet should decode")
    }

    fn constant(desc: &'static str, value: bool) -> Box<dyn Matcher> {
        Box::new(PredicateMatcher::new(desc, move |_packet, _ctx| value))
    }

    #[test]
    fn combinators_and_of_two_true_predicates_is_true() {
        let matcher = all(vec![
            constant("first true", true),
            constant("second true", true),
        ]);
        let packet = packet();
        let ctx = PacketContext::new();

        assert!(matcher.matches(&packet, &ctx));
        assert_eq!(matcher.describe(), "all(first true AND second true)");
    }

    #[test]
    fn combinators_and_with_one_false_predicate_is_false() {
        let matcher = all(vec![
            constant("first true", true),
            constant("second false", false),
        ]);
        let packet = packet();
        let ctx = PacketContext::new();

        assert!(!matcher.matches(&packet, &ctx));
        assert_eq!(matcher.describe(), "all(first true AND second false)");
    }

    #[test]
    fn combinators_or_is_true_when_either_predicate_is_true() {
        let matcher = any(vec![
            constant("first false", false),
            constant("second true", true),
        ]);
        let packet = packet();
        let ctx = PacketContext::new();

        assert!(matcher.matches(&packet, &ctx));
        assert_eq!(matcher.describe(), "any(first false OR second true)");
    }

    #[test]
    fn combinators_not_inverts_predicate() {
        let matcher = not(constant("always false", false));
        let packet = packet();
        let ctx = PacketContext::new();

        assert!(matcher.matches(&packet, &ctx));
        assert_eq!(matcher.describe(), "not(always false)");
    }

    #[test]
    fn combinators_extension_methods_compose_matchers() {
        let matcher = PredicateMatcher::new("first true", |_packet, _ctx| true)
            .and(PredicateMatcher::new("second true", |_packet, _ctx| true))
            .or(PredicateMatcher::new("fallback false", |_packet, _ctx| {
                false
            }))
            .not();
        let packet = packet();
        let ctx = PacketContext::new();

        assert!(!matcher.matches(&packet, &ctx));
        assert_eq!(
            matcher.describe(),
            "not(any(all(first true AND second true) OR fallback false))"
        );
    }
}
