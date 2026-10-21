use zeroize::Zeroizing;

use crate::VaultError;

pub(crate) const SALT_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl KdfParams {
    pub(crate) const DEFAULT: Self = Self {
        m_cost: 65_536,
        t_cost: 3,
        p_cost: 4,
    };

    pub(crate) fn m_cost(&self) -> u32 {
        self.m_cost
    }

    pub(crate) fn t_cost(&self) -> u32 {
        self.t_cost
    }

    pub(crate) fn p_cost(&self) -> u32 {
        self.p_cost
    }
}

pub(crate) struct KdfPolicy {
    m_cost: (u32, u32),
    t_cost: (u32, u32),
    p_cost: (u32, u32),
}

impl KdfPolicy {
    pub(crate) const PRODUCTION: Self = Self {
        m_cost: (19_456, 262_144),
        t_cost: (2, 8),
        p_cost: (1, 8),
    };

    #[cfg(test)]
    pub(crate) const TEST: Self = Self {
        m_cost: (64, 1_024),
        t_cost: (1, 3),
        p_cost: (1, 4),
    };

    pub(crate) fn admit(
        &self,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<KdfParams, VaultError> {
        if (self.m_cost.0..=self.m_cost.1).contains(&m_cost)
            && (self.t_cost.0..=self.t_cost.1).contains(&t_cost)
            && (self.p_cost.0..=self.p_cost.1).contains(&p_cost)
        {
            Ok(KdfParams {
                m_cost,
                t_cost,
                p_cost,
            })
        } else {
            Err(VaultError::KdfParamsOutOfPolicy {
                m_cost,
                t_cost,
                p_cost,
            })
        }
    }
}

pub(crate) trait KeyDerivation {
    fn derive(
        &self,
        passphrase: &[u8],
        salt: &[u8; SALT_LEN],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError>;
}

pub(crate) struct Argon2idDerivation;

impl KeyDerivation for Argon2idDerivation {
    fn derive(
        &self,
        passphrase: &[u8],
        salt: &[u8; SALT_LEN],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        neco_argon2::argon2id_hash_into(
            passphrase,
            salt,
            params.m_cost(),
            params.t_cost(),
            params.p_cost(),
            &mut key[..],
        )
        .map_err(VaultError::Argon2)?;
        Ok(key)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;

    use zeroize::Zeroizing;

    use super::{KdfParams, KeyDerivation, KEY_LEN, SALT_LEN};
    use crate::VaultError;

    pub(crate) struct FixedKeyDerivation(pub(crate) [u8; KEY_LEN]);

    impl KeyDerivation for FixedKeyDerivation {
        fn derive(
            &self,
            _passphrase: &[u8],
            _salt: &[u8; SALT_LEN],
            _params: &KdfParams,
        ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
            Ok(Zeroizing::new(self.0))
        }
    }

    pub(crate) struct CountingDerivation {
        calls: Cell<usize>,
        key: [u8; KEY_LEN],
    }

    impl CountingDerivation {
        pub(crate) fn new(key: [u8; KEY_LEN]) -> Self {
            Self {
                calls: Cell::new(0),
                key,
            }
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl KeyDerivation for CountingDerivation {
        fn derive(
            &self,
            _passphrase: &[u8],
            _salt: &[u8; SALT_LEN],
            _params: &KdfParams,
        ) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
            self.calls.set(self.calls.get() + 1);
            Ok(Zeroizing::new(self.key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat;

    fn assert_zeroizing(_: &Zeroizing<[u8; 32]>) {}

    fn kat_salt() -> [u8; SALT_LEN] {
        kat::unhex(kat::SALT).try_into().expect("16-byte salt")
    }

    #[test]
    fn argon2_key_matches_independent_reference() {
        let key_a = Argon2idDerivation
            .derive(
                kat::KAT_A_PASSPHRASE,
                &kat_salt(),
                &KdfPolicy::PRODUCTION
                    .admit(65_536, 3, 4)
                    .expect("KAT-A parameters"),
            )
            .expect("KAT-A key");
        assert_eq!(key_a[..], kat::unhex(kat::KAT_A_KEY)[..]);

        let key_c = Argon2idDerivation
            .derive(
                kat::KAT_C_PASSPHRASE,
                &kat_salt(),
                &KdfPolicy::TEST.admit(64, 1, 1).expect("KAT-C parameters"),
            )
            .expect("KAT-C key");
        assert_eq!(key_c[..], kat::unhex(kat::KAT_C_KEY)[..]);
    }

    #[test]
    fn policy_bounds_are_inclusive_and_report_header_values() {
        let policy = KdfPolicy::PRODUCTION;
        let (m_default, t_default, p_default) = (65_536, 3, 4);
        let out_of_policy = |m_cost, t_cost, p_cost| {
            Err(VaultError::KdfParamsOutOfPolicy {
                m_cost,
                t_cost,
                p_cost,
            })
        };

        for (m_cost, admitted) in [
            (0, false),
            (19_455, false),
            (19_456, true),
            (262_144, true),
            (262_145, false),
            (u32::MAX, false),
        ] {
            let result = policy.admit(m_cost, t_default, p_default);
            if admitted {
                let params = result.expect("m_cost inside the policy");
                assert_eq!(params.m_cost(), m_cost);
            } else {
                assert_eq!(result, out_of_policy(m_cost, t_default, p_default));
            }
        }
        for (t_cost, admitted) in [
            (0, false),
            (1, false),
            (2, true),
            (8, true),
            (9, false),
            (u32::MAX, false),
        ] {
            let result = policy.admit(m_default, t_cost, p_default);
            if admitted {
                let params = result.expect("t_cost inside the policy");
                assert_eq!(params.t_cost(), t_cost);
            } else {
                assert_eq!(result, out_of_policy(m_default, t_cost, p_default));
            }
        }
        for (p_cost, admitted) in [
            (0, false),
            (1, true),
            (8, true),
            (9, false),
            (u32::MAX, false),
        ] {
            let result = policy.admit(m_default, t_default, p_cost);
            if admitted {
                let params = result.expect("p_cost inside the policy");
                assert_eq!(params.p_cost(), p_cost);
            } else {
                assert_eq!(result, out_of_policy(m_default, t_default, p_cost));
            }
        }
        assert_eq!(policy.admit(0, 0, 0), out_of_policy(0, 0, 0));
    }

    #[test]
    fn policy_box_corners_satisfy_argon2_preconditions() {
        for policy in [KdfPolicy::PRODUCTION, KdfPolicy::TEST] {
            for m_cost in [policy.m_cost.0, policy.m_cost.1] {
                for t_cost in [policy.t_cost.0, policy.t_cost.1] {
                    for p_cost in [policy.p_cost.0, policy.p_cost.1] {
                        let params = policy
                            .admit(m_cost, t_cost, p_cost)
                            .expect("corner inside the policy");
                        assert!(u64::from(params.m_cost()) >= 8 * u64::from(params.p_cost()));
                        assert!(params.t_cost() >= 1);
                        assert!(params.p_cost() >= 1);
                    }
                }
            }
        }
    }

    #[test]
    fn default_params_are_the_documented_values() {
        assert_eq!(KdfParams::DEFAULT.m_cost(), 65_536);
        assert_eq!(KdfParams::DEFAULT.t_cost(), 3);
        assert_eq!(KdfParams::DEFAULT.p_cost(), 4);
        assert_eq!(
            KdfPolicy::PRODUCTION.admit(65_536, 3, 4),
            Ok(KdfParams::DEFAULT)
        );
    }

    #[test]
    fn derived_key_has_zeroizing_type() {
        let params = KdfPolicy::TEST.admit(64, 1, 1).expect("parameters");
        let key = Argon2idDerivation
            .derive(b"passphrase", &kat_salt(), &params)
            .expect("key");
        assert_zeroizing(&key);
    }

    #[test]
    fn argon2_failure_keeps_the_original_payload() {
        let result = Argon2idDerivation.derive(
            b"passphrase",
            &kat_salt(),
            &KdfParams {
                m_cost: 0,
                t_cost: 1,
                p_cost: 1,
            },
        );
        assert!(matches!(
            result,
            Err(VaultError::Argon2(
                neco_argon2::Argon2Error::InvalidParameter("m_cost")
            ))
        ));
    }
}
