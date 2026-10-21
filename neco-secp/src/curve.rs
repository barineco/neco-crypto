use neco_galois::{KnownPrimeModulus, U256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Secp256k1Field;

impl KnownPrimeModulus for Secp256k1Field {
    const MODULUS: U256 = U256 {
        l0: 0xFFFFFFFEFFFFFC2F,
        l1: 0xFFFFFFFFFFFFFFFF,
        l2: 0xFFFFFFFFFFFFFFFF,
        l3: 0xFFFFFFFFFFFFFFFF,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Secp256k1Order;

impl KnownPrimeModulus for Secp256k1Order {
    const MODULUS: U256 = U256 {
        l0: 0xBFD25E8CD0364141,
        l1: 0xBAAEDCE6AF48A03B,
        l2: 0xFFFFFFFFFFFFFFFE,
        l3: 0xFFFFFFFFFFFFFFFF,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use neco_galois::FieldContext;

    #[test]
    fn derived_montgomery_arithmetic() {
        let field = FieldContext::<Secp256k1Field>::new().unwrap();
        let r_squared = field.pow(field.reduce(U256::from_u64(2)), U256::from_u64(512));
        assert_eq!(
            field.to_u256(r_squared),
            U256 {
                l0: 0x000007A2000E90A1,
                l1: 0x0000000000000001,
                l2: 0x0000000000000000,
                l3: 0x0000000000000000,
            }
        );
        assert_eq!(field.to_u256(field.one()), U256::ONE);
        let p = field.reduce(Secp256k1Field::MODULUS);
        assert_eq!(p, field.zero());
        assert_eq!(
            field.mul(field.reduce(U256::from_u64(999)), p),
            field.zero()
        );
        assert_eq!(
            U256::cmp(Secp256k1Order::MODULUS, Secp256k1Field::MODULUS),
            core::cmp::Ordering::Less
        );
    }
}
