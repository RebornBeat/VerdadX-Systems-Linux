#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityLabel {
    pub sensitivity: SensitivityLevel,
    pub categories: HashSet<String>,
    pub compartments: HashSet<String>,
    pub owner: Option<String>,
    pub caveats: Vec<SecurityCaveat>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SensitivityLevel {
    Unclassified,
    Confidential,
    Secret,
    TopSecret,
    Custom(String, u32),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityCaveat {
    pub name: String,
    pub conditions: Vec<CaveatCondition>,
    pub expiration: Option<SystemTime>,
}

impl SecurityLabel {
    pub fn dominates(&self, other: &SecurityLabel) -> bool {
        // Check sensitivity level
        if !self.sensitivity.dominates(&other.sensitivity) {
            return false;
        }

        // Check categories
        if !self.categories.is_superset(&other.categories) {
            return false;
        }

        // Check compartments
        if !self.compartments.is_superset(&other.compartments) {
            return false;
        }

        // Check caveats
        self.check_caveats(&other.caveats)
    }

    pub fn check_caveats(&self, other_caveats: &[SecurityCaveat]) -> bool {
        for caveat in other_caveats {
            if !self.satisfies_caveat(caveat) {
                return false;
            }
        }
        true
    }
}
