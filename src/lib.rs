pub mod  models;
pub mod detector;

pub use detector::analyse;
pub use models::schema::AttackSchema;
pub use models::reporting::AlertReport;
pub use models::configuration::Arguments;
