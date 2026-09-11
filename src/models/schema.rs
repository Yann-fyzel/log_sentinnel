#[derive(Debug,Clone,Copy)]
pub enum AttackSchema{
    SqlInjection,
    DirectoryTraversal,
    Xss,
}

impl AttackSchema {
    pub fn as_pattern(&self) -> &'static str {
        match self {
            AttackSchema::SqlInjection => "UNION SELECT",
            AttackSchema::DirectoryTraversal => "../",
            AttackSchema::Xss => "<script>",
        }
    }
}

