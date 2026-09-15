//! HT NSS1/NSTS2 combining, IEEE802.11-2020 Table19-18 and Equation19-27.
//! These bounded algebra primitives establish no SIGNAL or MAC integrity.
use crate::radio::ComplexSample;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::radio) enum Error {
    NonFiniteInput,
    UnobservableChannel,
    NonFiniteResult,
}

fn finite(samples: &[ComplexSample]) -> Result<(), Error> {
    if samples.iter().any(|c| !c.i.is_finite() || !c.q.is_finite()) {
        Err(Error::NonFiniteInput)
    } else {
        Ok(())
    }
}

fn sample(i: f64, q: f64) -> Result<ComplexSample, Error> {
    let value = ComplexSample {
        i: i as f32,
        q: q as f32,
    };
    if !value.i.is_finite() || !value.q.is_finite() {
        Err(Error::NonFiniteResult)
    } else {
        Ok(value)
    }
}

/// Inputs have already had oscillator phase and known HT-LTF tone signs
/// removed. Column1 observes h1+h2; column2 observes -h1+h2.
pub(super) fn separate_training(observed: [ComplexSample; 2]) -> Result<[ComplexSample; 2], Error> {
    finite(&observed)?;
    let [a, b] = observed;
    Ok([
        sample(
            (f64::from(a.i) - f64::from(b.i)) / 2.,
            (f64::from(a.q) - f64::from(b.q)) / 2.,
        )?,
        sample(
            (f64::from(a.i) + f64::from(b.i)) / 2.,
            (f64::from(a.q) + f64::from(b.q)) / 2.,
        )?,
    ])
}

/// Recover two consecutive data symbols at one tone. Effective channels
/// include cyclic shift/spatial mapping and must remain coherent across the
/// pair. Received symbols must already have common phase/clock drift removed.
pub(in crate::radio) fn recover_pair(
    channels: [ComplexSample; 2],
    received: [ComplexSample; 2],
) -> Result<[ComplexSample; 2], Error> {
    finite(&channels)?;
    finite(&received)?;
    let [h1, h2] = channels;
    let [y0, y1] = received;
    let [a, b, c, d] = [h1.i, h1.q, h2.i, h2.q].map(f64::from);
    let [e, f, g, h] = [y0.i, y0.q, y1.i, y1.q].map(f64::from);
    // f64 intermediates bound products of every finite f32 input, including
    // subnormal channel power. Only the final recovered symbols narrow to f32.
    let power = a * a + b * b + c * c + d * d;
    if power == 0. {
        return Err(Error::UnobservableChannel);
    }
    Ok([
        sample(
            (a * e + b * f + c * g + d * h) / power,
            (a * f - b * e + d * g - c * h) / power,
        )?,
        sample(
            (a * g + b * h - c * e - d * f) / power,
            (a * h - b * g - d * e + c * f) / power,
        )?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(actual: ComplexSample, expected: ComplexSample) {
        assert!(
            (actual.i - expected.i).abs() < 2e-6,
            "{actual:?} != {expected:?}"
        );
        assert!(
            (actual.q - expected.q).abs() < 2e-6,
            "{actual:?} != {expected:?}"
        );
    }

    #[test]
    fn radio_stbc_independent_pairs_and_training() {
        let rows: Vec<_> = include_str!("../../../../tests/fixtures/iq/stbc-pairs.tsv")
            .lines()
            .skip(1)
            .collect();
        assert_eq!(rows.len(), 2400);
        for row in rows {
            let c: Vec<_> = row.split('\t').collect();
            assert_eq!(c.len(), 17);
            let at = |index: usize| ComplexSample {
                i: c[1 + 2 * index].parse().unwrap(),
                q: c[2 + 2 * index].parse().unwrap(),
            };
            let channels = [at(0), at(1)];
            let trained = separate_training([at(6), at(7)]).unwrap();
            for (actual, expected) in trained.into_iter().zip(channels) {
                close(actual, expected);
            }
            for estimated in [channels, trained] {
                let recovered = recover_pair(estimated, [at(2), at(3)]).unwrap();
                close(recovered[0], at(4));
                close(recovered[1], at(5));
            }
        }
    }

    #[test]
    fn radio_stbc_finite_bounds_and_unobservable_channels() {
        let zero = ComplexSample::ZERO;
        let one = ComplexSample { i: 1., q: 0. };
        assert!(matches!(
            recover_pair([zero, zero], [one, one]),
            Err(Error::UnobservableChannel)
        ));
        for scale in [f32::MAX, f32::MIN_POSITIVE, f32::from_bits(1)] {
            let value = ComplexSample { i: scale, q: 0. };
            let recovered = recover_pair([value, zero], [value, value]).unwrap();
            close(recovered[0], one);
            close(recovered[1], one);
            close(separate_training([value, value]).unwrap()[1], value);
        }
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let invalid = ComplexSample { i: bad, q: 0. };
            assert!(matches!(
                recover_pair([invalid, one], [one, one]),
                Err(Error::NonFiniteInput)
            ));
            assert!(matches!(
                recover_pair([one, zero], [one, invalid]),
                Err(Error::NonFiniteInput)
            ));
            assert!(matches!(
                separate_training([one, invalid]),
                Err(Error::NonFiniteInput)
            ));
        }
        assert!(matches!(
            recover_pair(
                [
                    ComplexSample {
                        i: f32::from_bits(1),
                        q: 0.
                    },
                    zero
                ],
                [ComplexSample { i: f32::MAX, q: 0. }, one]
            ),
            Err(Error::NonFiniteResult)
        ));
    }
}
