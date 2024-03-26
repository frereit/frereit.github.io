#![allow(clippy::module_name_repetitions)]
use wasm_bindgen::prelude::*;

pub mod f128;
pub mod factorize;

use crate::f128::{F128Element, F128Polynomial};

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]
#[must_use]
pub fn find_zeros(hex_coefficients: Vec<String>) -> Vec<String> {
    let coefficients: Vec<F128Element> = hex_coefficients
        .iter()
        .map(|x| F128Element::from_block(hex::decode(x).unwrap().try_into().unwrap()))
        .collect();
    let polynomial = F128Polynomial::new(coefficients).to_monic();
    let zeros = factorize::roots(&polynomial);
    zeros.iter().map(|x| hex::encode(x.to_block())).collect()
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]
#[must_use]
pub fn square_free(hex_coefficients: Vec<String>) -> Vec<String> {
    let coefficients: Vec<F128Element> = hex_coefficients
        .iter()
        .map(|x| F128Element::from_block(hex::decode(x).unwrap().try_into().unwrap()))
        .collect();
    let polynomial = F128Polynomial::new(coefficients).to_monic();
    let square_free = factorize::square_free_factorization(&polynomial);
    square_free
        .0
        .iter()
        .map(|x| hex::encode(x.to_block()))
        .collect()
}

#[wasm_bindgen]
#[allow(clippy::needless_pass_by_value, clippy::missing_panics_doc)]
#[must_use]
pub fn distinct_degree(hex_coefficients: Vec<String>) -> Vec<String> {
    let coefficients: Vec<F128Element> = hex_coefficients
        .iter()
        .map(|x| F128Element::from_block(hex::decode(x).unwrap().try_into().unwrap()))
        .collect();
    let polynomial = F128Polynomial::new(coefficients).to_monic();
    let square_free = factorize::square_free_factorization(&polynomial);
    let distinct_degree = factorize::distinct_degree_factorize(&square_free);
    
    // HACK: wasm-bindgen doesn't allow for Vec<Vec<String>> return types.
    // So we return a 1D array, where each polynomial is immediately followed
    // by the degree of its factors, and then an empty string to signify the end of the polynomial.
    let mut out = Vec::new();
    for (poly, deg) in distinct_degree {
        out.extend(poly.0.iter().map(|x| hex::encode(x.to_block())));
        out.push(deg.to_string());
        out.push("".to_string());
    }

    out
}
