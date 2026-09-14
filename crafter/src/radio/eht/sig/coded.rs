//! Rate-one-half EHT-SIG blocks with an independent BCC state per block.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    NonFinite { index: usize },
    Truncated { required: usize, available: usize },
    Erased,
}

pub(in crate::radio) struct Blocks<'a> {
    metrics: &'a [f32],
    cursor: usize,
}

impl<'a> Blocks<'a> {
    pub(in crate::radio) fn new(metrics: &'a [f32]) -> Result<Self, Error> {
        if let Some(index) = metrics.iter().position(|metric| !metric.is_finite()) {
            return Err(Error::NonFinite { index });
        }
        Ok(Self { metrics, cursor: 0 })
    }

    pub(in crate::radio) fn bits<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let required = 2 * N;
        let available = self.metrics.len().saturating_sub(self.cursor);
        if available < required {
            return Err(Error::Truncated {
                required,
                available,
            });
        }
        let metrics = &self.metrics[self.cursor..self.cursor + required];
        let scale = metrics
            .iter()
            .map(|metric| metric.abs())
            .fold(0f32, f32::max);
        self.cursor += required;
        if scale == 0. {
            return Err(Error::Erased);
        }
        let pairs = std::array::from_fn::<_, N, _>(|index| {
            [metrics[2 * index] / scale, metrics[2 * index + 1] / scale]
        });
        Ok(crate::radio::signal::decode_bcc(&pairs))
    }
}
