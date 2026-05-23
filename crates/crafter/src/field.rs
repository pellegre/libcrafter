//! Field state tracking for protocol encoders.

/// The state of a protocol field.
///
/// Protocol builders use this to distinguish fields that may be auto-filled
/// from fields the caller set explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field<T> {
    /// No value has been assigned.
    Unset,
    /// The library assigned a default value.
    Defaulted(T),
    /// The caller explicitly supplied a value.
    User(T),
}

/// A compact copyable view of a [`Field`]'s state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldState {
    /// No value has been assigned.
    Unset,
    /// The library assigned a default value.
    Defaulted,
    /// The caller explicitly supplied a value.
    User,
}

impl<T> Default for Field<T> {
    fn default() -> Self {
        Self::Unset
    }
}

impl<T> Field<T> {
    /// Create an unset field.
    pub const fn unset() -> Self {
        Self::Unset
    }

    /// Create a field with a library default value.
    pub const fn defaulted(value: T) -> Self {
        Self::Defaulted(value)
    }

    /// Create a field with a caller-supplied value.
    pub const fn user(value: T) -> Self {
        Self::User(value)
    }

    /// Return a copyable description of the field state.
    pub const fn state(&self) -> FieldState {
        match self {
            Self::Unset => FieldState::Unset,
            Self::Defaulted(_) => FieldState::Defaulted,
            Self::User(_) => FieldState::User,
        }
    }

    /// Return true when the field has no value.
    pub const fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }

    /// Return true when the field has a library default value.
    pub const fn is_defaulted(&self) -> bool {
        matches!(self, Self::Defaulted(_))
    }

    /// Return true when the caller explicitly supplied the value.
    pub const fn is_user_set(&self) -> bool {
        matches!(self, Self::User(_))
    }

    /// Read the current value, if any.
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Unset => None,
            Self::Defaulted(value) | Self::User(value) => Some(value),
        }
    }

    /// Mutably read the current value, if any.
    pub fn value_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Unset => None,
            Self::Defaulted(value) | Self::User(value) => Some(value),
        }
    }

    /// Assign a library default only when the field is currently unset.
    pub fn set_default_if_unset(&mut self, value: T) -> bool {
        if self.is_unset() {
            *self = Self::Defaulted(value);
            true
        } else {
            false
        }
    }

    /// Assign or replace the caller-supplied value.
    pub fn set_user(&mut self, value: T) {
        *self = Self::User(value);
    }

    /// Consume the field and return the value, if any.
    pub fn into_value(self) -> Option<T> {
        match self {
            Self::Unset => None,
            Self::Defaulted(value) | Self::User(value) => Some(value),
        }
    }
}

impl<T> From<T> for Field<T> {
    fn from(value: T) -> Self {
        Self::User(value)
    }
}

#[cfg(test)]
mod field_primitives {
    use super::{Field, FieldState};

    #[test]
    fn unset_fields_have_no_value() {
        let field = Field::<u16>::unset();

        assert_eq!(field.state(), FieldState::Unset);
        assert!(field.is_unset());
        assert_eq!(field.value(), None);
    }

    #[test]
    fn defaults_do_not_overwrite_user_values() {
        let mut field = Field::user(7u8);

        assert!(!field.set_default_if_unset(9));
        assert_eq!(field.state(), FieldState::User);
        assert_eq!(field.value(), Some(&7));
    }

    #[test]
    fn defaults_fill_only_unset_values() {
        let mut field = Field::unset();

        assert!(field.set_default_if_unset(9u8));
        assert_eq!(field.state(), FieldState::Defaulted);
        assert_eq!(field.into_value(), Some(9));
    }

    #[test]
    fn user_assignment_replaces_defaults() {
        let mut field = Field::defaulted(9u16);

        field.set_user(42);

        assert_eq!(field.state(), FieldState::User);
        assert_eq!(field.value(), Some(&42));
    }
}
