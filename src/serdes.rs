#[cfg(any(feature = "alloc", feature = "std"))]
use crate::*;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};
use elliptic_curve::{Group, PrimeField, group::GroupEncoding, subtle::CtOption};
use serde::{
    self, Deserializer, Serializer,
    de::{Error as DError, SeqAccess, Visitor},
    ser::SerializeTuple,
};
use serdect::{array, slice};

/// Serialize and deserialize a prime field element.
pub mod prime_field {
    use super::*;
    use elliptic_curve::PrimeField;

    /// Serialize a prime field element.
    pub fn serialize<F, S>(f: &F, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        F: PrimeField,
    {
        serialize_(f.to_repr(), s)
    }

    /// Deserialize a prime field element.
    pub fn deserialize<'de, F, D>(d: D) -> Result<F, D::Error>
    where
        D: Deserializer<'de>,
        F: PrimeField,
    {
        let repr = deserialize_(d)?;
        Option::from(F::from_repr(repr)).ok_or(DError::custom("invalid prime field element"))
    }
}

/// Serialize and deserialize a prime field element array.
pub mod prime_field_array {
    use super::*;

    /// Serialize a prime field element array.
    pub fn serialize<F, S, const N: usize>(input: &[F; N], s: S) -> Result<S::Ok, S::Error>
    where
        F: PrimeField,
        S: Serializer,
    {
        let seq = input.iter().map(|f| f.to_repr());
        serialize_tuple(seq, s, N)
    }

    /// Deserialize a prime field element array.
    pub fn deserialize<'de, F, D, const N: usize>(d: D) -> Result<[F; N], D::Error>
    where
        F: PrimeField,
        D: Deserializer<'de>,
    {
        let output = deserialize_pushable::<F::Repr, F, _, heapless::Vec<F, N>, _>(
            F::from_repr,
            DeserializeMethod::Tuple,
            d,
            N,
        )?;
        output
            .into_array::<N>()
            .map_err(|_| DError::custom("unable to convert to array"))
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a prime field element vector.
pub mod prime_field_vec {
    use super::*;

    /// Serialize a prime field element vector.
    pub fn serialize<F, S>(vec: &[F], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        F: PrimeField,
    {
        let seq = vec.iter().map(|f| f.to_repr());
        serialize_seq(seq, s, vec.len())
    }

    /// Deserialize a prime field element vector.
    pub fn deserialize<'de, F, D>(d: D) -> Result<Vec<F>, D::Error>
    where
        D: Deserializer<'de>,
        F: PrimeField,
    {
        deserialize_pushable::<F::Repr, F, _, Vec<F>, _>(F::from_repr, DeserializeMethod::Seq, d, 0)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a prime field element boxed slice.
pub mod prime_field_boxed_slice {
    use super::*;

    /// Serialize a prime field element boxed slice.
    pub fn serialize<F, S>(slice: &[F], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        F: PrimeField,
    {
        let seq = slice.iter().map(|f| f.to_repr());
        serialize_seq(seq, s, slice.len())
    }

    /// Deserialize a prime field element boxed slice.
    pub fn deserialize<'de, F, D>(d: D) -> Result<Box<[F]>, D::Error>
    where
        D: Deserializer<'de>,
        F: PrimeField,
    {
        prime_field_vec::deserialize(d).map(|v| v.into_boxed_slice())
    }
}

/// Serialize and deserialize a group element.
pub mod group {
    use super::*;

    /// Serialize a group element.
    pub fn serialize<G, S>(g: &G, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        G: Group + GroupEncoding,
    {
        serialize_(g.to_bytes(), s)
    }

    /// Deserialize a group element.
    pub fn deserialize<'de, G, D>(d: D) -> Result<G, D::Error>
    where
        D: Deserializer<'de>,
        G: Group + GroupEncoding,
    {
        let bytes = deserialize_(d)?;
        Option::from(G::from_bytes(&bytes)).ok_or(DError::custom("invalid group element"))
    }
}

/// Serialize and deserialize a group element array.
pub mod group_array {
    use super::*;

    /// Serialize a group element array.
    pub fn serialize<G, S, const N: usize>(input: &[G; N], s: S) -> Result<S::Ok, S::Error>
    where
        G: Group + GroupEncoding,
        S: Serializer,
    {
        let seq = input.iter().map(|g| g.to_bytes());
        serialize_tuple(seq, s, N)
    }

    /// Deserialize a group element array.
    pub fn deserialize<'de, G, D, const N: usize>(d: D) -> Result<[G; N], D::Error>
    where
        G: Group + GroupEncoding,
        D: Deserializer<'de>,
    {
        let output = deserialize_pushable::<G::Repr, G, _, heapless::Vec<G, N>, _>(
            |repr| G::from_bytes(&repr),
            DeserializeMethod::Tuple,
            d,
            N,
        )?;
        output
            .into_array::<N>()
            .map_err(|_| DError::custom("unable to convert to array"))
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a group element vector.
pub mod group_vec {
    use super::*;

    /// Serialize a group element vector.
    pub fn serialize<G, S>(vec: &[G], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        G: Group + GroupEncoding,
    {
        let seq = vec.iter().map(|g| g.to_bytes());
        serialize_seq(seq, s, vec.len())
    }

    /// Deserialize a group element vector.
    pub fn deserialize<'de, G, D>(d: D) -> Result<Vec<G>, D::Error>
    where
        D: Deserializer<'de>,
        G: Group + GroupEncoding,
    {
        deserialize_pushable::<G::Repr, G, _, Vec<G>, _>(
            |repr| G::from_bytes(&repr),
            DeserializeMethod::Seq,
            d,
            0,
        )
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a group element boxed slice.
pub mod group_boxed_slice {
    use super::*;

    /// Serialize a group element boxed slice.
    pub fn serialize<G, S>(slice: &[G], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        G: Group + GroupEncoding,
    {
        let seq = slice.iter().map(|g| g.to_bytes());
        serialize_seq(seq, s, slice.len())
    }

    /// Deserialize a group element boxed slice.
    pub fn deserialize<'de, G, D>(d: D) -> Result<Box<[G]>, D::Error>
    where
        D: Deserializer<'de>,
        G: Group + GroupEncoding,
    {
        group_vec::deserialize(d).map(|v| v.into_boxed_slice())
    }
}

fn serialize_<B, S>(bytes: B, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
{
    array::serialize_hex_lower_or_bin(&bytes, s)
}

struct Bytes<'a>(&'a [u8]);

impl serde::Serialize for Bytes<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        slice::serialize_hex_lower_or_bin(&self.0, serializer)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn serialize_seq<B, IB, S>(sequence: IB, s: S, length: usize) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
    IB: Iterator<Item = B>,
{
    use serde::ser::SerializeSeq;
    if s.is_human_readable() {
        let mut seq = s.serialize_seq(Some(length))?;
        for b in sequence {
            seq.serialize_element(&Bytes(b.as_ref()))?;
        }
        seq.end()
    } else {
        let byte_length = length * B::default().as_ref().len();
        let mut seq = s.serialize_seq(Some(byte_length))?;
        for g in sequence {
            for b in g.as_ref() {
                seq.serialize_element(b)?;
            }
        }
        seq.end()
    }
}

fn serialize_tuple<B, IB, S>(sequence: IB, s: S, length: usize) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
    IB: Iterator<Item = B>,
{
    if s.is_human_readable() {
        let mut seq = s.serialize_tuple(length)?;
        for b in sequence {
            seq.serialize_element(&Bytes(b.as_ref()))?;
        }
        seq.end()
    } else {
        let byte_length = length * B::default().as_ref().len();
        let mut seq = s.serialize_tuple(byte_length)?;
        for g in sequence {
            for b in g.as_ref() {
                seq.serialize_element(b)?;
            }
        }
        seq.end()
    }
}

fn deserialize_<'de, B: AsRef<[u8]> + AsMut<[u8]> + Default, D: Deserializer<'de>>(
    d: D,
) -> Result<B, D::Error> {
    let mut repr = B::default();
    array::deserialize_hex_or_bin(repr.as_mut(), d)?;
    Ok(repr)
}

fn deserialize_pushable<'de, B, O, FO, P, D>(
    fo: FO,
    method: DeserializeMethod,
    d: D,
    expected_entries: usize,
) -> Result<P, D::Error>
where
    D: Deserializer<'de>,
    B: AsRef<[u8]> + AsMut<[u8]> + Default,
    O: Copy,
    FO: FnMut(B) -> CtOption<O>,
    P: Pushable<O>,
{
    if d.is_human_readable() {
        struct StrSeqVisitor<B, O, FO, P> {
            fo: FO,
            marker: PhantomData<(B, O, P)>,
        }

        impl<'de, B, O, FO, P> Visitor<'de> for StrSeqVisitor<B, O, FO, P>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
            O: Copy,
            FO: FnMut(B) -> CtOption<O>,
            P: Pushable<O>,
        {
            type Value = P;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "an array of hex strings")
            }

            fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = P::default();
                while let Some(element) = seq.next_element::<slice::HexLowerOrBin>()? {
                    let mut repr = B::default();
                    if element.as_ref().len() != repr.as_ref().len() {
                        return Err(DError::custom("invalid length"));
                    }
                    repr.as_mut().copy_from_slice(element.as_ref());
                    let a =
                        Option::from((self.fo)(repr)).ok_or(DError::custom("invalid element"))?;
                    arr.push(a)?;
                }
                Ok(arr)
            }
        }
        method.run_fn(
            d,
            StrSeqVisitor {
                fo,
                marker: PhantomData::<(B, O, P)>,
            },
            expected_entries,
        )
    } else {
        struct ByteSeqVisitor<B, O, FO, P> {
            fo: FO,
            marker: PhantomData<(B, O, P)>,
        }

        impl<'de, B, O, FO, P> Visitor<'de> for ByteSeqVisitor<B, O, FO, P>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
            O: Copy,
            P: Pushable<O>,
            FO: FnMut(B) -> CtOption<O>,
        {
            type Value = P;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a sequence of bytes")
            }

            fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = P::default();

                loop {
                    let mut repr = B::default();

                    let mut exit = false;
                    for (i, r) in repr.as_mut().iter_mut().enumerate() {
                        let e = seq.next_element::<u8>()?;
                        if i == 0 && e.is_none() {
                            exit = true;
                            break;
                        }
                        *r = e.ok_or_else(|| DError::invalid_length(i, &self))?;
                    }
                    if exit {
                        break;
                    }
                    let a =
                        Option::from((self.fo)(repr)).ok_or(DError::custom("invalid element"))?;
                    arr.push(a)?;
                }

                Ok(arr)
            }
        }
        let repr = B::default();
        let chunk = repr.as_ref().len();
        method.run_fn(
            d,
            ByteSeqVisitor::<B, O, FO, P> {
                fo,
                marker: PhantomData::<(B, O, P)>,
            },
            expected_entries * chunk,
        )
    }
}

trait Pushable<T>: Default {
    fn push<E: DError>(&mut self, value: T) -> Result<(), E>;
}

impl<T: Debug, const N: usize> Pushable<T> for heapless::Vec<T, N> {
    fn push<E: DError>(&mut self, value: T) -> Result<(), E> {
        heapless::Vec::push(self, value).map_err(|_| DError::custom("too many elements"))
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<T> Pushable<T> for Vec<T> {
    fn push<E: DError>(&mut self, value: T) -> Result<(), E> {
        Vec::push(self, value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
enum DeserializeMethod {
    Tuple,
    #[cfg(any(feature = "alloc", feature = "std"))]
    Seq,
}

impl DeserializeMethod {
    fn run_fn<'de, D, V>(self, d: D, v: V, length: usize) -> Result<V::Value, D::Error>
    where
        D: Deserializer<'de>,
        V: Visitor<'de>,
    {
        match self {
            Self::Tuple => d.deserialize_tuple(length, v),
            #[cfg(any(feature = "alloc", feature = "std"))]
            Self::Seq => d.deserialize_seq(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::Field;
    use rstest::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct TestStruct<G: Group + GroupEncoding> {
        #[serde(with = "prime_field")]
        scalar: G::Scalar,
        #[serde(with = "group")]
        point: G,
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    struct TestStructVec<G: Group + GroupEncoding> {
        #[serde(with = "prime_field_vec")]
        scalar: Vec<G::Scalar>,
        #[serde(with = "group_vec")]
        point: Vec<G>,
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[rstest]
    #[case::k256(k256::ProjectivePoint::default())]
    #[case::p256(p256::ProjectivePoint::default())]
    #[case::p384(p384::ProjectivePoint::default())]
    #[case::p521(p521::ProjectivePoint::default())]
    #[case::bp256_r1(bp256::r1::ProjectivePoint::default())]
    #[case::bp256_t1(bp256::t1::ProjectivePoint::default())]
    #[case::bp384_r1(bp384::r1::ProjectivePoint::default())]
    #[case::bp384_t1(bp384::t1::ProjectivePoint::default())]
    fn single_struct<G: Group + GroupEncoding>(#[case] _g: G) {
        let test_struct = TestStruct {
            scalar: <G::Scalar as Field>::ONE,
            point: G::generator(),
        };

        // postcard
        let res = postcard::to_stdvec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = postcard::from_bytes(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // bare
        let res = serde_bare::to_vec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_bare::from_slice(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // cbor
        let res = serde_cbor::to_vec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_cbor::from_slice(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // ciborium
        let mut buffer = Vec::with_capacity(86);
        let res = ciborium::into_writer(&test_struct, &mut buffer);
        assert!(res.is_ok());
        let res = ciborium::from_reader(buffer.as_slice());
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // json
        let res = serde_json::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_json::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // yaml
        let res = serde_yaml::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_yaml::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // toml
        let res = toml::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = toml::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn struct_vec() {
        let test_struct = TestStructVec {
            scalar: vec![<k256::Scalar as Field>::ONE; 32],
            point: vec![k256::ProjectivePoint::GENERATOR; 32],
        };

        // postcard
        let res = postcard::to_stdvec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = postcard::from_bytes(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // bare
        let res = serde_bare::to_vec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_bare::from_slice(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // cbor
        let res = serde_cbor::to_vec(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_cbor::from_slice(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // ciborium
        let mut buffer = Vec::with_capacity(86);
        let res = ciborium::into_writer(&test_struct, &mut buffer);
        assert!(res.is_ok());
        let res = ciborium::from_reader(buffer.as_slice());
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // json
        let res = serde_json::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_json::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // yaml
        let res = serde_yaml::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = serde_yaml::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);

        // toml
        let res = toml::to_string(&test_struct);
        assert!(res.is_ok());
        let output = res.expect("serialization round trip should succeed");
        let res = toml::from_str(&output);
        assert!(res.is_ok());
        let test_struct2 = res.expect("serialization round trip should succeed");
        assert_eq!(test_struct, test_struct2);
    }
}
