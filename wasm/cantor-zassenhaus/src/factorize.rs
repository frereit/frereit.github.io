use crate::f128::{F128Element, F128Polynomial};

#[allow(clippy::missing_panics_doc)] // Panic is unreachable
#[must_use]
pub fn roots(polynomial: &F128Polynomial) -> Vec<F128Element> {
    let factors = factor(polynomial);
    factors
        .iter()
        .map(F128Polynomial::to_monic)
        .filter(|x| x.0.len() == 2)
        .map(|x| x.0.first().copied().expect("filter ensures length is 2"))
        .collect()
}

#[must_use]
pub fn factor(polynomial: &F128Polynomial) -> Vec<F128Polynomial> {
    // First, get the square free part
    let square_free = square_free_factorization(polynomial);

    // Then, find all equal degree factors
    let equal_degree_factors: Vec<_> = distinct_degree_factorize(&square_free);

    // Finally, split all equal degree factors into irreducible factors
    let mut factors = vec![];
    for (poly, degrees) in equal_degree_factors {
        if degrees == poly.0.len() - 1 {
            // irreducible
            factors.push(poly);
        } else {
            factors.extend(equal_degree_factorize(&poly, degrees));
        }
    }
    factors
}

#[must_use]
pub fn distinct_degree_factorize(polynomial: &F128Polynomial) -> Vec<(F128Polynomial, usize)> {
    // https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization
    let mut factors = vec![];
    let mut poly_star = polynomial.to_monic();
    let mut i = 1;
    let mut x = F128Polynomial::new(vec![F128Element(0), F128Element(1)]);
    while poly_star.0.len() > 2 * i {
        x = x.powmod(1 << 127, &poly_star);
        x = x.powmod(2, &poly_star);
        let factor = F128Polynomial::gcd(
            poly_star.clone(),
            &x + F128Polynomial::new(vec![F128Element(0), F128Element(1)]),
        );

        if factor.0.len() > 1 {
            poly_star = poly_star / &factor;
            factors.push((factor, i));
        }
        i += 1;
    }

    if poly_star != F128Polynomial::one() {
        let len = poly_star.0.len() - 1;
        factors.push((poly_star, len));
    }

    if factors.is_empty() {
        factors.push((polynomial.to_monic(), 1));
    }

    factors
}

#[must_use]
#[allow(clippy::missing_panics_doc)] // Panic is unreachable
pub fn square_free_factorization(polynomial: &F128Polynomial) -> F128Polynomial {
    let mut result = F128Polynomial::one();
    let polynomial = polynomial.to_monic();

    let mut odd_free = F128Polynomial::gcd(polynomial.clone(), polynomial.derivative());
    let mut w = polynomial / &odd_free;
    let mut i = 1;
    while w != F128Polynomial::one() {
        let y = F128Polynomial::gcd(w.clone(), odd_free.clone());
        let factor = w / &y;
        for _ in 0..i {
            result = result * &factor;
        }
        w = y.to_monic();
        odd_free = odd_free / &y;
        i += 1;
    }

    if odd_free.to_monic() != F128Polynomial::one() {
        let sqrt = odd_free
            .sqrt()
            .expect("This must be a square, by definition");
        let sqrt_factorized = square_free_factorization(&sqrt);
        result = result * sqrt_factorized;
    }

    result
}

#[must_use]
pub fn equal_degree_factorize(polynomial: &F128Polynomial, degree: usize) -> Vec<F128Polynomial> {
    let mut factors = vec![polynomial.clone()];
    while factors.len() != (polynomial.0.len() - 1) / degree {
        let rand = F128Polynomial::random(polynomial.0.len() - 1);

        // 0x5555_5555_5555_5555_5555_5555_5555_5555 = (2^128)/3.
        let mut g = rand
            .powmod(0x5555_5555_5555_5555_5555_5555_5555_5555, polynomial);
        let r_pow_p_minus_1_div_3 = g.clone();
        for _ in 1..degree {
            g = g.powmod(1 << 127, polynomial);
            g = g.powmod(2, polynomial);
            g = &g * &r_pow_p_minus_1_div_3;
            g = g % polynomial;
        }
        for factor in factors.clone().iter().filter(|x| x.0.len() != degree) {
            let gcd = F128Polynomial::gcd(factor.clone(), g.clone() + F128Polynomial::one());
            if gcd.0.len() > 1 && gcd.0.len() < factor.0.len() {
                factors.push(factor / &gcd);
                factors.push(gcd);
                factors.retain(|x| x != factor);
                break;
            }
        }
    }
    factors
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_zeros() {
        let poly = F128Polynomial::new(vec![
            F128Element(44658497621430546465552067582925486430),
            F128Element(8775212720526497844413474915127362008),
            F128Element(159882420825161619330844250700542647343),
            F128Element(41370730215558825575033146660536451072),
            F128Element(1),
        ]);
        let factors = factor(&poly);
        let zeros = factors
            .iter()
            .map(|x| x.to_monic())
            .flat_map(|x| x.0.first().cloned())
            .collect::<Vec<_>>();
        assert_eq!(zeros.len(), 4);
        assert!(zeros.contains(&&F128Element(0xf77db57b000000000000000000000000)));
        assert!(zeros.contains(&&F128Element(0x77ff0300000000000000000000000000)));
        assert!(zeros.contains(&&F128Element(0xb3d50000000000000000000000000000)));
        assert!(zeros.contains(&&F128Element(0x2c480000000000000000000000000000)));
    }

    #[test]
    fn test_degree_two_factors() {
        let poly = F128Polynomial::new(vec![
            F128Element(73900111365138678687523612352372067482),
            F128Element(334766111689601553458100587475591389000),
            F128Element(228496597381527898477099281086147557357),
            F128Element(291173289036958711705635792801734525307),
            F128Element(3169191554852581922920349882495773301),
        ]);
        let factors = factor(&poly);
        assert_eq!(factors.len(), 2);
        assert_eq!(
            factors[0].to_monic() * factors[1].to_monic(),
            poly.to_monic()
        );
    }

    #[test]
    fn test_irreducible() {
        let poly = F128Polynomial::new(vec![
            F128Element(113621441705815645649065805383454706182),
            F128Element(172079072389954286753473129753044519229),
            F128Element(16589814480579588750760940242536969201),
            F128Element(94764393397259253859387367773756005363),
            F128Element(54975018509952452188641731551862247930),
        ]);
        let factors = factor(&poly);
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].to_monic(), poly.to_monic());
    }

    #[test]
    fn test_random_factors() {
        for _ in 0..200 {
            let poly = F128Polynomial::random(5);
            let factors = factor(&poly);
            let product = factors
                .iter()
                .fold(F128Polynomial::one(), |acc, x| acc * x);
            assert_eq!(product.to_monic(), poly.to_monic());
        }
    }

    #[test]
    fn test_find_square_free_part() {
        let a = F128Polynomial(vec![
            F128Element(165561879346020818106439165970613955905),
            F128Element(1),
        ]);
        let b = F128Polynomial(vec![
            F128Element(261064362113442048867529397787216873321),
            F128Element(1),
        ]);
        let poly = (&a * &a) * &b;
        let square_free = square_free_factorization(&poly);
        assert_eq!(square_free.to_monic(), (a * b).to_monic());
    }

    #[test]
    fn test_distinct_degree_factorization() {
        let a = F128Polynomial(vec![
            F128Element(52330733814030467326643484500469848294),
            F128Element(165561879346020818106439165970613955905),
        ]);
        let b = F128Polynomial(vec![
            F128Element(233328233774988783342728909394263641625),
            F128Element(274493643517918769777437023706639486239),
            F128Element(161141815452699709889925938662260829158),
        ]);
        let poly = &a * &b;
        let factor = distinct_degree_factorize(&poly);
        assert_eq!(factor.len(), 2);
        assert!(factor.iter().any(|x| x.0.to_monic() == a.to_monic()));
        assert!(factor.iter().any(|x| x.0.to_monic() == b.to_monic()));
    }
}
