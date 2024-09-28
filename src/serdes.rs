#[cfg(any(feature = "alloc", feature = "std"))]
use crate::*;
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    slice, str,
};
use elliptic_curve::{group::GroupEncoding, subtle::CtOption, Group, PrimeField};
use serde::{
    de::{Error as DError, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserializer, Serializer,
};

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
    pub fn serialize<F, S>(vec: &Vec<F>, s: S) -> Result<S::Ok, S::Error>
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
        deserialize_pushable::<F::Repr, F, _, Vec<F>, _>(F::from_repr, DeserializeMethod::Seq, d)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a prime field element boxed slice.
pub mod prime_field_boxed_slice {
    use super::*;

    /// Serialize a prime field element boxed slice.
    pub fn serialize<F, S>(slice: &Box<[F]>, s: S) -> Result<S::Ok, S::Error>
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
    pub fn serialize<G, S>(vec: &Vec<G>, s: S) -> Result<S::Ok, S::Error>
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
        )
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
/// Serialize and deserialize a group element boxed slice.
pub mod group_boxed_slice {
    use super::*;

    /// Serialize a group element boxed slice.
    pub fn serialize<G, S>(slice: &Box<[G]>, s: S) -> Result<S::Ok, S::Error>
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
    if s.is_human_readable() {
        let converter = HexConverter::new(bytes);
        s.serialize_str(converter.as_str())
    } else {
        s.serialize_bytes(bytes.as_ref())
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
            seq.serialize_element(&hex::encode(b.as_ref()))?;
        }
        seq.end()
    } else {
        let mut seq = s.serialize_seq(Some(length))?;
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
            let converter = HexConverter::new(b);
            seq.serialize_element(converter.as_str())?;
        }
        seq.end()
    } else {
        let mut seq = s.serialize_tuple(length)?;
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
    if d.is_human_readable() {
        struct StrVisitor<B: AsRef<[u8]> + AsMut<[u8]> + Default>(PhantomData<B>);

        impl<'de, B> Visitor<'de> for StrVisitor<B>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
        {
            type Value = B;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a {} length hex string", B::default().as_ref().len() * 2)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: DError,
            {
                let mut repr = B::default();
                let length = repr.as_ref().len();
                if v.len() != length * 2 {
                    return Err(DError::custom("invalid length"));
                }
                hex::decode_to_slice(v, repr.as_mut())
                    .map_err(|_| DError::custom("invalid input"))?;
                Ok(repr)
            }
        }
        d.deserialize_str(StrVisitor(PhantomData))
    } else {
        struct ByteVisitor<B: AsRef<[u8]> + AsMut<[u8]> + Default>(PhantomData<B>);

        impl<'de, B> Visitor<'de> for ByteVisitor<B>
        where
            B: AsRef<[u8]> + AsMut<[u8]> + Default,
        {
            type Value = B;

            fn expecting(&self, f: &mut Formatter) -> fmt::Result {
                write!(f, "a {} byte", B::default().as_ref().len())
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut repr = B::default();
                if v.len() != repr.as_ref().len() {
                    return Err(serde::de::Error::custom("invalid length"));
                }
                repr.as_mut().copy_from_slice(v);
                Ok(repr)
            }
        }

        d.deserialize_bytes(ByteVisitor(PhantomData))
    }
}

fn deserialize_pushable<'de, B, O, FO, P, D>(
    fo: FO,
    method: DeserializeMethod,
    d: D,
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
                while let Some(element) = seq.next_element::<&str>()? {
                    let mut repr = B::default();
                    hex::decode_to_slice(element, repr.as_mut())
                        .map_err(|_| DError::custom("invalid hex string"))?;
                    let a =
                        Option::from((self.fo)(repr)).ok_or(DError::custom("invalid element"))?;
                    arr.push(a);
                }
                if arr.entries() <= P::expected_size() {
                    return Err(DError::custom("invalid number of elements"));
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
            P::expected_size(),
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
                    arr.push(a);
                }
                if arr.entries() < P::expected_size() {
                    return Err(DError::custom("invalid number of elements"));
                }

                Ok(arr)
            }
        }
        let repr = B::default();
        let chunk = repr.as_ref().len();
        d.deserialize_tuple(
            P::expected_size() * chunk,
            ByteSeqVisitor::<B, O, FO, P> {
                fo,
                marker: PhantomData::<(B, O, P)>,
            },
        )
    }
}

struct HexConverter<B> {
    first_half: B,
    last_half: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]> + Default> HexConverter<B> {
    pub fn new(bytes: B) -> Self {
        let mid = bytes.as_ref().len() / 2;
        let mut first_half = B::default();
        let mut last_half = B::default();
        let _ = hex::encode_to_slice(&bytes.as_ref()[..mid], first_half.as_mut());
        let _ = hex::encode_to_slice(&bytes.as_ref()[mid..], last_half.as_mut());
        Self {
            first_half,
            last_half,
        }
    }

    pub fn as_str(&self) -> &str {
        let length = self.last_half.as_ref().len();
        unsafe {
            str::from_utf8_unchecked(slice::from_raw_parts(
                self.first_half.as_ref().as_ptr(),
                length * 2,
            ))
        }
    }
}

trait Pushable<T>: Default {
    fn push(&mut self, value: T);
    fn entries(&self) -> usize;
    fn expected_size() -> usize;
}

impl<T: Debug, const N: usize> Pushable<T> for heapless::Vec<T, N> {
    fn push(&mut self, value: T) {
        heapless::Vec::push(self, value).expect("should've allocated more");
    }

    fn entries(&self) -> usize {
        (*self).len()
    }

    fn expected_size() -> usize {
        N
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl<T> Pushable<T> for Vec<T> {
    fn push(&mut self, value: T) {
        Vec::push(self, value)
    }

    fn entries(&self) -> usize {
        self.len()
    }

    fn expected_size() -> usize {
        0
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
