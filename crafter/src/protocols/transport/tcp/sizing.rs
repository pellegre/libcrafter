//! TCP segment sizing and option-budget helpers.

pub(crate) fn padded_options_len(len: usize) -> usize {
    (len + 3) & !3
}
