use neco_galois::{KnownPrimeModulus, U256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P256Field;

impl KnownPrimeModulus for P256Field {
    const MODULUS: U256 = U256 {
        l0: 0xFFFFFFFFFFFFFFFF,
        l1: 0x00000000FFFFFFFF,
        l2: 0x0000000000000000,
        l3: 0xFFFFFFFF00000001,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct P256Order;

impl KnownPrimeModulus for P256Order {
    const MODULUS: U256 = U256 {
        l0: 0xF3B9CAC2FC632551,
        l1: 0xBCE6FAADA7179E84,
        l2: 0xFFFFFFFFFFFFFFFF,
        l3: 0xFFFFFFFF00000000,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use neco_galois::FieldContext;

    #[test]
    fn derived_montgomery_arithmetic() {
        let field = FieldContext::<P256Field>::new().unwrap();
        let r_squared = field.pow(field.reduce(U256::from_u64(2)), U256::from_u64(512));
        assert_eq!(
            field.to_u256(r_squared),
            U256 {
                l0: 0x0000000000000003,
                l1: 0xFFFFFFFBFFFFFFFF,
                l2: 0xFFFFFFFFFFFFFFFE,
                l3: 0x00000004FFFFFFFD,
            }
        );
        assert_eq!(field.to_u256(field.one()), U256::ONE);
        let p = field.reduce(P256Field::MODULUS);
        assert_eq!(p, field.zero());
        assert_eq!(
            field.mul(field.reduce(U256::from_u64(999)), p),
            field.zero()
        );
        assert_eq!(
            U256::cmp(P256Order::MODULUS, P256Field::MODULUS),
            core::cmp::Ordering::Less
        );
    }
}
