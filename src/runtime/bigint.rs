//! Arbitrary-precision signed integers for VM numbers.
//!
//! libauth uses JavaScript `bigint` for VM numbers. Following BCH 2025, VM
//! numbers may be up to 10,000 bytes, so the port needs an in-repo big integer
//! implementation. Values are stored as a sign and little-endian base-2^32
//! magnitude.

use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    /// `false` for zero and positive values.
    negative: bool,
    /// Little-endian magnitude limbs; trailing zero limbs are removed.
    limbs: Vec<u32>,
}


impl BigInt {
    pub fn zero() -> Self {
        BigInt {
            negative: false,
            limbs: Vec::new(),
        }
    }

    pub fn from_i64(value: i64) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let negative = value < 0;
        let magnitude = value.unsigned_abs();
        let mut result = BigInt {
            negative,
            limbs: vec![magnitude as u32, (magnitude >> 32) as u32],
        };
        result.normalize();
        result
    }

    pub fn from_u64(value: u64) -> Self {
        let mut result = BigInt {
            negative: false,
            limbs: vec![value as u32, (value >> 32) as u32],
        };
        result.normalize();
        result
    }

    /// `BigInt(number)`: the exact value of an integral number. Like
    /// JavaScript, throws a `RangeError` (here, panics) for fractional and
    /// non-finite numbers.
    pub fn from_number(value: f64) -> Self {
        if !value.is_finite() || value.trunc() != value {
            panic!(
                "RangeError: The number {} cannot be converted to a BigInt because it is not an integer",
                crate::runtime::number::number_to_string(value)
            );
        }
        let two_to_the_53 = 9_007_199_254_740_992.0;
        if value.abs() < two_to_the_53 {
            return Self::from_i64(value as i64);
        }
        // value = significand * 2^exponent, with exponent >= 1 here.
        let bits = value.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) - 1075;
        let significand = (bits & ((1 << 52) - 1)) | (1 << 52);
        let magnitude = Self::from_u64(significand).shl(exponent);
        if value < 0.0 { magnitude.negate() } else { magnitude }
    }

    /// `BigInt.asUintN(bits, bigint)`: the value modulo 2^bits.
    pub fn as_uint_n(bits: u64, value: &Self) -> Self {
        let modulus = Self::from_u64(1).shl(bits);
        let (_, remainder) = value.div_mod(&modulus);
        if remainder.is_negative() { remainder.add(&modulus) } else { remainder }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.negative = false;
        }
    }

    fn from_magnitude(mut limbs: Vec<u32>, negative: bool) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        let negative = negative && !limbs.is_empty();
        BigInt { negative, limbs }
    }

    /// The number of significant bits in the magnitude.
    pub fn bit_length(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    pub fn negate(&self) -> Self {
        BigInt {
            negative: !self.negative && !self.limbs.is_empty(),
            limbs: self.limbs.clone(),
        }
    }

    pub fn abs(&self) -> Self {
        BigInt {
            negative: false,
            limbs: self.limbs.clone(),
        }
    }

    fn cmp_magnitude(a: &[u32], b: &[u32]) -> Ordering {
        if a.len() != b.len() {
            return a.len().cmp(&b.len());
        }
        for index in (0..a.len()).rev() {
            if a[index] != b[index] {
                return a[index].cmp(&b[index]);
            }
        }
        Ordering::Equal
    }

    pub fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => Self::cmp_magnitude(&self.limbs, &other.limbs),
            (true, true) => Self::cmp_magnitude(&other.limbs, &self.limbs),
        }
    }

    fn add_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
        let length = core::cmp::max(a.len(), b.len());
        let mut result = Vec::with_capacity(length + 1);
        let mut carry = 0_u64;
        for index in 0..length {
            let sum = *a.get(index).unwrap_or(&0) as u64
                + *b.get(index).unwrap_or(&0) as u64
                + carry;
            result.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            result.push(carry as u32);
        }
        result
    }

    /// Subtract `b` from `a`; requires `a >= b`.
    fn sub_magnitude(a: &[u32], b: &[u32]) -> Vec<u32> {
        let mut result = Vec::with_capacity(a.len());
        let mut borrow = 0_i64;
        for index in 0..a.len() {
            let difference = a[index] as i64 - *b.get(index).unwrap_or(&0) as i64 - borrow;
            if difference < 0 {
                result.push((difference + (1_i64 << 32)) as u32);
                borrow = 1;
            } else {
                result.push(difference as u32);
                borrow = 0;
            }
        }
        while result.last() == Some(&0) {
            result.pop();
        }
        result
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.negative == other.negative {
            return Self::from_magnitude(
                Self::add_magnitude(&self.limbs, &other.limbs),
                self.negative,
            );
        }
        match Self::cmp_magnitude(&self.limbs, &other.limbs) {
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self::from_magnitude(
                Self::sub_magnitude(&self.limbs, &other.limbs),
                self.negative,
            ),
            Ordering::Less => Self::from_magnitude(
                Self::sub_magnitude(&other.limbs, &self.limbs),
                other.negative,
            ),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut result = vec![0_u32; self.limbs.len() + other.limbs.len()];
        for (index_a, &limb_a) in self.limbs.iter().enumerate() {
            let mut carry = 0_u64;
            for (index_b, &limb_b) in other.limbs.iter().enumerate() {
                let position = index_a + index_b;
                let product =
                    limb_a as u64 * limb_b as u64 + result[position] as u64 + carry;
                result[position] = product as u32;
                carry = product >> 32;
            }
            let mut position = index_a + other.limbs.len();
            while carry != 0 {
                let sum = result[position] as u64 + carry;
                result[position] = sum as u32;
                carry = sum >> 32;
                position += 1;
                if position == result.len() && carry != 0 {
                    result.push(0);
                }
            }
        }
        Self::from_magnitude(result, self.negative != other.negative)
    }

    /// Divide by `divisor`, returning (quotient, remainder) truncated toward zero.
    pub fn div_mod(&self, divisor: &Self) -> (Self, Self) {
        assert!(!divisor.is_zero(), "division by zero");
        let (quotient, remainder) = Self::div_mod_magnitude(&self.limbs, &divisor.limbs);
        (
            Self::from_magnitude(quotient, self.negative != divisor.negative),
            Self::from_magnitude(remainder, self.negative),
        )
    }

    fn div_mod_magnitude(dividend: &[u32], divisor: &[u32]) -> (Vec<u32>, Vec<u32>) {
        if Self::cmp_magnitude(dividend, divisor) == Ordering::Less {
            return (Vec::new(), dividend.to_vec());
        }
        if divisor.len() == 1 {
            let divisor_limb = divisor[0] as u64;
            let mut quotient = vec![0_u32; dividend.len()];
            let mut remainder = 0_u64;
            for index in (0..dividend.len()).rev() {
                let current = (remainder << 32) | dividend[index] as u64;
                quotient[index] = (current / divisor_limb) as u32;
                remainder = current % divisor_limb;
            }
            while quotient.last() == Some(&0) {
                quotient.pop();
            }
            let remainder = if remainder == 0 {
                Vec::new()
            } else {
                vec![remainder as u32]
            };
            return (quotient, remainder);
        }
        // Knuth's Algorithm D.
        let n = divisor.len();
        let m = dividend.len() - n;
        let shift = divisor[n - 1].leading_zeros();
        let normalize = |value: &[u32]| -> Vec<u32> {
            if shift == 0 {
                let mut result = value.to_vec();
                result.push(0);
                return result;
            }
            let mut result = Vec::with_capacity(value.len() + 1);
            let mut carry = 0_u32;
            for &limb in value {
                result.push((limb << shift) | carry);
                carry = limb >> (32 - shift);
            }
            result.push(carry);
            result
        };
        let mut u = normalize(dividend);
        let v = normalize(divisor);
        let mut quotient = vec![0_u32; m + 1];
        let base = 1_u64 << 32;
        for j in (0..=m).rev() {
            let numerator = ((u[j + n] as u64) << 32) | u[j + n - 1] as u64;
            let mut q_hat = numerator / v[n - 1] as u64;
            let mut r_hat = numerator % v[n - 1] as u64;
            while q_hat >= base
                || q_hat * v[n - 2] as u64 > ((r_hat << 32) | u[j + n - 2] as u64)
            {
                q_hat -= 1;
                r_hat += v[n - 1] as u64;
                if r_hat >= base {
                    break;
                }
            }
            // Multiply and subtract.
            let mut borrow = 0_i64;
            let mut carry = 0_u64;
            for i in 0..n {
                let product = q_hat * v[i] as u64 + carry;
                carry = product >> 32;
                let difference = u[i + j] as i64 - (product as u32) as i64 - borrow;
                if difference < 0 {
                    u_digit_set(&mut u, i + j, (difference + (1_i64 << 32)) as u32);
                    borrow = 1;
                } else {
                    u_digit_set(&mut u, i + j, difference as u32);
                    borrow = 0;
                }
            }
            let difference = u[j + n] as i64 - carry as i64 - borrow;
            if difference < 0 {
                u_digit_set(&mut u, j + n, (difference + (1_i64 << 32)) as u32);
                // Add back.
                q_hat -= 1;
                let mut carry = 0_u64;
                for i in 0..n {
                    let sum = u[i + j] as u64 + v[i] as u64 + carry;
                    u_digit_set(&mut u, i + j, sum as u32);
                    carry = sum >> 32;
                }
                let top = u[j + n] as u64 + carry;
                u_digit_set(&mut u, j + n, top as u32);
            } else {
                u_digit_set(&mut u, j + n, difference as u32);
            }
            quotient[j] = q_hat as u32;
        }
        while quotient.last() == Some(&0) {
            quotient.pop();
        }
        // Denormalize the remainder.
        let mut remainder = u[..n].to_vec();
        if shift != 0 {
            let mut carry = 0_u32;
            for index in (0..n).rev() {
                let limb = remainder[index];
                remainder[index] = (limb >> shift) | carry;
                carry = limb << (32 - shift);
            }
        }
        while remainder.last() == Some(&0) {
            remainder.pop();
        }
        (quotient, remainder)
    }

    pub fn shl(&self, bits: u64) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        if bits / 32 > usize::MAX as u64 / 2 {
            // Guard against absurd shift counts before allocation.
            return Self::zero();
        }
        let limb_shift = (bits / 32) as usize;
        let bit_shift = (bits % 32) as u32;
        let mut result = vec![0_u32; limb_shift];
        if bit_shift == 0 {
            result.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0_u32;
            for &limb in &self.limbs {
                result.push((limb << bit_shift) | carry);
                carry = limb >> (32 - bit_shift);
            }
            if carry != 0 {
                result.push(carry);
            }
        }
        Self::from_magnitude(result, self.negative)
    }

    /// Arithmetic right shift (rounds toward negative infinity, like JS BigInt).
    pub fn shr(&self, bits: u64) -> Self {
        if self.is_zero() || bits == 0 {
            return self.clone();
        }
        let magnitude = if bits >= (self.limbs.len() as u64) * 32 {
            Vec::new()
        } else {
            let limb_shift = (bits / 32) as usize;
            let bit_shift = (bits % 32) as u32;
            let mut result = self.limbs[limb_shift..].to_vec();
            if bit_shift != 0 {
                let mut carry = 0_u32;
                for index in (0..result.len()).rev() {
                    let limb = result[index];
                    result[index] = (limb >> bit_shift) | carry;
                    carry = limb << (32 - bit_shift);
                }
            }
            while result.last() == Some(&0) {
                result.pop();
            }
            result
        };
        if !self.negative {
            return Self::from_magnitude(magnitude, false);
        }
        // Negative shift: floor division by 2^bits. If any low bit was set, add one to the magnitude.
        let mut remainder_nonzero = false;
        let full_limbs = (bits / 32) as usize;
        for &limb in self.limbs.iter().take(full_limbs) {
            if limb != 0 {
                remainder_nonzero = true;
            }
        }
        let partial = (bits % 32) as u32;
        if partial != 0 && full_limbs < self.limbs.len() {
            if self.limbs[full_limbs] & ((1_u32 << partial) - 1) != 0 {
                remainder_nonzero = true;
            }
        }
        let magnitude = if remainder_nonzero {
            Self::add_magnitude(&magnitude, &[1])
        } else {
            magnitude
        };
        Self::from_magnitude(magnitude, true)
    }

    pub fn pow(&self, exponent: u32) -> Self {
        let mut result = BigInt::from_u64(1);
        let mut base = self.clone();
        let mut power = exponent;
        while power > 0 {
            if power & 1 == 1 {
                result = result.mul(&base);
            }
            power >>= 1;
            if power > 0 {
                base = base.mul(&base);
            }
        }
        result
    }

    /// `BigInt(string)`: parse a string of decimal digits (with an optional
    /// sign) or of `0x`/`0o`/`0b`-prefixed digits, ignoring surrounding
    /// whitespace (an empty string is `0n`). Returns the `SyntaxError` message
    /// JavaScript would throw for invalid input.
    pub fn parse(text: &str) -> Result<Self, String> {
        let syntax_error = || Err(format!("SyntaxError: Cannot convert {text} to a BigInt"));
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(Self::zero());
        }
        let lowercase = trimmed.to_ascii_lowercase();
        let (radix, digits, negative) = if let Some(digits) = lowercase.strip_prefix("0x") {
            (16, digits.to_string(), false)
        } else if let Some(digits) = lowercase.strip_prefix("0o") {
            (8, digits.to_string(), false)
        } else if let Some(digits) = lowercase.strip_prefix("0b") {
            (2, digits.to_string(), false)
        } else if let Some(digits) = lowercase.strip_prefix('-') {
            (10, digits.to_string(), true)
        } else {
            (10, lowercase.strip_prefix('+').unwrap_or(&lowercase).to_string(), false)
        };
        if digits.is_empty() {
            return syntax_error();
        }
        let radix_value = Self::from_u64(radix as u64);
        let mut value = Self::zero();
        for character in digits.chars() {
            let Some(digit) = character.to_digit(radix) else {
                return syntax_error();
            };
            value = value.mul(&radix_value).add(&Self::from_u64(digit as u64));
        }
        Ok(if negative { value.negate() } else { value })
    }

    /// `base ** exponent` (JavaScript's exponentiation operator), which throws
    /// a `RangeError` (here: panics) for negative exponents and for results
    /// exceeding the maximum `BigInt` size.
    pub fn exponentiate(&self, exponent: &Self) -> Self {
        if exponent.is_negative() {
            panic!("RangeError: Exponent must be non-negative");
        }
        let one = BigInt::from_u64(1);
        if exponent.is_zero() {
            return one;
        }
        if self.is_zero() || *self == one {
            return self.clone();
        }
        if *self == one.negate() {
            let exponent_is_even = exponent.limbs.first().is_some_and(|limb| limb & 1 == 0);
            return if exponent_is_even { one } else { self.clone() };
        }
        match exponent.to_u64().and_then(|exponent| u32::try_from(exponent).ok()) {
            Some(exponent) => self.pow(exponent),
            None => panic!("RangeError: Maximum BigInt size exceeded"),
        }
    }

    pub fn to_i64(&self) -> Option<i64> {
        if self.limbs.len() > 2 {
            return None;
        }
        let magnitude =
            *self.limbs.first().unwrap_or(&0) as u64 + ((*self.limbs.get(1).unwrap_or(&0) as u64) << 32);
        if self.negative {
            if magnitude > (i64::MAX as u64) + 1 {
                None
            } else {
                Some((magnitude as i64).wrapping_neg())
            }
        } else if magnitude > i64::MAX as u64 {
            None
        } else {
            Some(magnitude as i64)
        }
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.negative || self.limbs.len() > 2 {
            return None;
        }
        Some(*self.limbs.first().unwrap_or(&0) as u64 + ((*self.limbs.get(1).unwrap_or(&0) as u64) << 32))
    }

    /// Construct a non-negative value from its little-endian magnitude bytes.
    ///
    /// (libauth assembles VM numbers from little-endian words with `<<` and
    /// `|`; this is the equivalent linear-time construction.)
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let limbs = bytes
            .chunks(4)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0_u32, |value, (index, byte)| value | (*byte as u32) << (8 * index))
            })
            .collect();
        Self::from_magnitude(limbs, false)
    }

    /// The minimal little-endian bytes of the magnitude (empty for zero).
    pub fn to_bytes_le(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.limbs.len() * 4);
        for limb in &self.limbs {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        bytes
    }

    /// `a & b` for non-negative operands.
    pub fn bitand(&self, other: &Self) -> Self {
        debug_assert!(!self.negative && !other.negative);
        let limbs = self.limbs.iter().zip(&other.limbs).map(|(a, b)| a & b).collect();
        Self::from_magnitude(limbs, false)
    }

    /// `a | b` for non-negative operands.
    pub fn bitor(&self, other: &Self) -> Self {
        debug_assert!(!self.negative && !other.negative);
        let length = self.limbs.len().max(other.limbs.len());
        let limbs = (0..length)
            .map(|index| {
                self.limbs.get(index).copied().unwrap_or(0) | other.limbs.get(index).copied().unwrap_or(0)
            })
            .collect();
        Self::from_magnitude(limbs, false)
    }

    /// `Number(bigint)`: the nearest IEEE-754 double (ties to even).
    pub fn to_number(&self) -> f64 {
        if let Some(value) = self.to_i64() {
            return value as f64;
        }
        // Decimal parsing is correctly rounded (and yields infinity when out
        // of range), matching `Number(bigint)`.
        self.to_string().parse::<f64>().unwrap_or(f64::NAN)
    }

    /// `bigint.toString(radix)` for a radix between 2 and 36.
    pub fn to_string_radix(&self, radix: u32) -> String {
        assert!((2..=36).contains(&radix), "radix must be between 2 and 36");
        if self.is_zero() {
            return "0".to_string();
        }
        // Divide by the largest power of `radix` which fits in a limb.
        let (chunk_divisor, chunk_digits) = {
            let (mut divisor, mut count) = (radix as u64, 1);
            while divisor * radix as u64 <= u32::MAX as u64 {
                divisor *= radix as u64;
                count += 1;
            }
            (divisor, count)
        };
        let mut digits = Vec::new();
        let mut magnitude = self.limbs.clone();
        while !magnitude.is_empty() {
            let mut remainder = 0_u64;
            for index in (0..magnitude.len()).rev() {
                let current = (remainder << 32) | magnitude[index] as u64;
                magnitude[index] = (current / chunk_divisor) as u32;
                remainder = current % chunk_divisor;
            }
            while magnitude.last() == Some(&0) {
                magnitude.pop();
            }
            for _ in 0..chunk_digits {
                if magnitude.is_empty() && remainder == 0 {
                    break;
                }
                digits.push(
                    std::char::from_digit((remainder % radix as u64) as u32, radix)
                        .expect("valid digit"),
                );
                remainder /= radix as u64;
            }
        }
        if self.negative {
            digits.push('-');
        }
        digits.iter().rev().collect()
    }

}

fn u_digit_set(buffer: &mut [u32], index: usize, value: u32) {
    if index < buffer.len() {
        buffer[index] = value;
    }
}

/// `${bigint}`: the decimal representation.
impl std::fmt::Display for BigInt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_string_radix(10))
    }
}
