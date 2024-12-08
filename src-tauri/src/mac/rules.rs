#[derive(Debug, Clone)]
pub struct AccessRule {
    subject_pattern: SubjectPattern,
    object_pattern: ObjectPattern,
    access_types: HashSet<AccessType>,
    conditions: Vec<AccessCondition>,
    action: AccessAction,
    priority: u32,
}

#[derive(Debug, Clone)]
pub enum AccessCondition {
    TimeRange(TimeRange),
    Location(LocationConstraint),
    SystemLoad(LoadConstraint),
    CustomCondition(Box<dyn Fn(&SecurityContext, &SecurityContext) -> bool + Send + Sync>),
}

impl AccessRule {
    pub fn matches(
        &self,
        subject: &SecurityContext,
        object: &SecurityContext,
        access: &AccessType,
    ) -> bool {
        // Check if access type is covered by this rule
        if !self.access_types.contains(access) {
            return false;
        }

        // Check subject pattern
        if !self.subject_pattern.matches(subject) {
            return false;
        }

        // Check object pattern
        if !self.object_pattern.matches(object) {
            return false;
        }

        // Check conditions
        self.check_conditions(subject, object)
    }

    fn check_conditions(&self, subject: &SecurityContext, object: &SecurityContext) -> bool {
        for condition in &self.conditions {
            if !condition.evaluate(subject, object) {
                return false;
            }
        }
        true
    }
}
