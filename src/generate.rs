//! Generating a key pair with a certificate, self-signed or signed by
//! another private key of the keystore: the key algorithms, and adding the
//! result to the open keystore once its form is filled in.
use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crown::{
    asn1::{
        der,
        oid::{self, ObjectIdentifier},
    },
    bn::Bn,
    ec::{self, CurveId},
    ecdh,
    error::{CryptoError, CryptoResult},
    rng::Rng,
    rsa::{RsaPrivateKey, der::rsa_private_key_der},
    x509::keys::encode_ec_private_key,
};
use ratatui::crossterm::event::KeyEvent;
use zeroize::Zeroizing;

use crate::{
    App,
    certificate_form::{Form, Outcome},
    editing::{Action, AliasPrompt},
    key_import::Key,
    save::OsRng,
    signing,
};

/// The kind and size of a generated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Rsa(usize),
    Ec(CurveId),
    Ed25519,
}

impl Algorithm {
    pub const ALL: [Self; 7] = [
        Self::Rsa(2048),
        Self::Rsa(3072),
        Self::Rsa(4096),
        Self::Ec(CurveId::P256),
        Self::Ec(CurveId::P384),
        Self::Ec(CurveId::P521),
        Self::Ed25519,
    ];

    pub fn label(self) -> String {
        match self {
            Self::Rsa(bits) => format!("RSA {bits}"),
            Self::Ec(CurveId::P256) => "EC P-256".into(),
            Self::Ec(CurveId::P384) => "EC P-384".into(),
            Self::Ec(CurveId::P521) => "EC P-521".into(),
            Self::Ed25519 => "Ed25519".into(),
        }
    }
}

const NOT_GENERATED: &str = "The key pair could not be generated.";

/// A new private key of this algorithm, as PKCS #8.
pub fn key_pair(algorithm: Algorithm, rng: &mut impl Rng) -> Result<Key, String> {
    match algorithm {
        Algorithm::Rsa(bits) => rsa(bits, rng),
        Algorithm::Ec(curve) => elliptic(curve, rng),
        Algorithm::Ed25519 => {
            let mut seed = Zeroizing::new([0; 32]);
            rng.fill_bytes(&mut *seed);
            let key = Zeroizing::new(der::octet_string(&*seed));
            Ok(pkcs8(&der::oid(&object(oid::OID_ED25519)), &key))
        }
    }
    .map_err(|_| NOT_GENERATED.into())
}

fn object(arcs: &[u64]) -> ObjectIdentifier {
    ObjectIdentifier::new(arcs).expect("a constant object identifier")
}

/// The PKCS #8 structure around a private key in its algorithm's own
/// encoding; `algorithm` is the content of the algorithm identifier.
fn pkcs8(algorithm: &[u8], key: &[u8]) -> Key {
    let key = Zeroizing::new(der::octet_string(key));
    let content =
        Zeroizing::new([&der::integer(&[0])[..], &der::sequence(algorithm), &key[..]].concat());
    Zeroizing::new(der::sequence(&content))
}

fn elliptic(curve: CurveId, rng: &mut impl Rng) -> CryptoResult<Key> {
    let arcs = match curve {
        CurveId::P256 => oid::OID_SECP256R1,
        CurveId::P384 => oid::OID_SECP384R1,
        CurveId::P521 => oid::OID_SECP521R1,
    };
    let (scalar, public) = ecdh::generate(curve, rng)?;
    let public = public.to_bytes_with(&ec::curve(curve));
    let key = Zeroizing::new(encode_ec_private_key(arcs, &scalar, Some(&public))?);
    let algorithm = [
        der::oid(&object(oid::OID_EC_PUBLIC_KEY)),
        der::oid(&object(arcs)),
    ]
    .concat();
    Ok(pkcs8(&algorithm, &key))
}

/// Passes random bytes on, keeping every request of one length: the
/// candidates the RSA primes are chosen from.
struct Recorder<'a, R> {
    rng: &'a mut R,
    length: usize,
    draws: Vec<Zeroizing<Vec<u8>>>,
}

impl<R: Rng> Rng for Recorder<'_, R> {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        self.rng.fill_bytes(out);
        if out.len() == self.length {
            self.draws.push(Zeroizing::new(out.to_vec()));
        }
    }
}

/// The prime among the recorded candidates that divides `modulus`.
/// The generator sets a candidate's two highest bits and its lowest one.
fn factor(modulus: &Bn, draws: &[Zeroizing<Vec<u8>>]) -> Option<Bn> {
    draws.iter().find_map(|draw| {
        let mut bytes = draw.clone();
        *bytes.first_mut()? |= 0xc0;
        *bytes.last_mut()? |= 1;
        let candidate = Bn::from_be_bytes(&bytes);
        let (_, rest) = modulus.divrem(&candidate).ok()?;
        rest.is_zero().then_some(candidate)
    })
}

/// An RSA key of `bits` bits with the public exponent 65537.
///
/// The library generates the key but does not give out its private parts,
/// so they are worked out again from the modulus and the prime found among
/// the random candidates the generator drew.
fn rsa(bits: usize, rng: &mut impl Rng) -> CryptoResult<Key> {
    const EXPONENT: u64 = 65537;
    let mut recorder = Recorder {
        rng,
        length: bits / 16,
        draws: Vec::new(),
    };
    let key = RsaPrivateKey::generate(bits, EXPONENT, &mut recorder)?;
    let modulus = Bn::from_be_bytes(&key.public().n());
    let found = factor(&modulus, &recorder.draws)
        .ok_or(CryptoError::StrError("the generated primes were not found"))?;
    let (other, _) = modulus.divrem(&found)?;
    let (p, q) = if found.lt(&other) {
        (other, found)
    } else {
        (found, other)
    };
    let one = Bn::one();
    let (p1, q1) = (p.sub(&one)?, q.sub(&one)?);
    let exponent = Bn::from_u64(EXPONENT);
    let d = exponent.mod_inverse(&p1.mul(&q1))?;
    let bytes = |number: &Bn| Zeroizing::new(number.to_be_bytes());
    let key = Zeroizing::new(rsa_private_key_der(
        &modulus.to_be_bytes(),
        &exponent.to_be_bytes(),
        &bytes(&d),
        &bytes(&p),
        &bytes(&q),
        &bytes(&d.modulus(&p1)),
        &bytes(&d.modulus(&q1)),
        &bytes(&q.mod_inverse(&p)?),
    ));
    let algorithm = [der::oid(&object(oid::OID_RSA_ENCRYPTION)), der::null()].concat();
    Ok(pkcs8(&algorithm, &key))
}

/// A filled-in form whose key pair is not generated yet.
pub struct Pending {
    form: Form,
    algorithm: Algorithm,
    request: signing::Request,
}

impl Pending {
    /// The form to go back to.
    pub fn into_form(self) -> Form {
        self.form
    }
}

impl App {
    /// Opens the form for a new key pair.
    pub(crate) fn ask_generate(&mut self) {
        if self.changeable() {
            self.generating = Some(Form::default());
        }
    }

    pub(crate) fn handle_generate(&mut self, key: KeyEvent) {
        let Some(form) = &mut self.generating else {
            return;
        };
        match form.handle_key(key) {
            Outcome::Editing => {}
            Outcome::Cancelled => self.generating = None,
            // The alias is asked first, so that no generated key is thrown away.
            Outcome::Submitted(algorithm, request) => {
                if let Some(form) = self.generating.take() {
                    self.alias_prompt = Some(AliasPrompt {
                        alias: form.common_name().to_lowercase(),
                        action: Action::Generate(Box::new(Pending {
                            form,
                            algorithm,
                            request,
                        })),
                    });
                }
            }
        }
    }

    /// Starts generating the key pair of a filled-in form, named `alias`,
    /// on a background thread. The keystore is read-only until it is done.
    pub(crate) fn start_generation(&mut self, alias: String, pending: Box<Pending>) {
        let Pending {
            algorithm,
            request,
            form,
        } = *pending;
        let signer = form.signer();
        let issuer = match self.signer(signer) {
            Ok(issuer) => issuer,
            Err(error) => {
                self.message = Some((error, true));
                return;
            }
        };
        let signer_alias = signer
            .and_then(|index| self.entries.get(index))
            .map(|entry| entry.alias.clone());
        self.generation = Some(Job::start(alias, algorithm, signer_alias, move || {
            generate(algorithm, &request, issuer)
        }));
    }

    /// The private key at `signer` and its chain, read on the UI thread.
    fn signer(&self, signer: Option<usize>) -> Result<Option<Generated>, String> {
        let Some(index) = signer else {
            return Ok(None);
        };
        let document = self.document.as_ref().ok_or("No keystore is open.")?;
        let entry = self.entries.get(index).ok_or("The signing key is gone.")?;
        let key = document
            .private_key(index)
            .map_err(|error| format!("Nothing signed: the key '{}' {error}.", entry.alias))?;
        let chain = entry.certificates().to_vec();
        if chain.is_empty() {
            return Err("The signing key has no certificate.".into());
        }
        Ok(Some((key, chain)))
    }

    /// The line the status bar keeps for a key pair being generated.
    pub(crate) fn generation_status(&self) -> Option<String> {
        self.generation.as_ref().map(Job::status)
    }

    /// Adds the generated key pair once its thread is done. Returns whether
    /// a generation finished.
    pub(crate) fn poll_generation(&mut self) -> bool {
        let Some(job) = &self.generation else {
            return false;
        };
        let result = match job.result.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => Err(NOT_GENERATED.into()),
        };
        let Some(job) = self.generation.take() else {
            return false;
        };
        let added = result.and_then(|(key, chain)| {
            let document = self.document.as_mut().ok_or("No keystore is open.")?;
            document.import_key_pair(&mut self.entries, job.alias.clone(), &key, &chain)
        });
        match added {
            Ok(to) => {
                let mut message = format!(
                    "Generated {} key pair '{}'",
                    job.algorithm.label(),
                    job.alias
                );
                if let Some(signer) = &job.signer {
                    message.push_str(&format!(", signed by '{signer}'"));
                }
                message.push('.');
                self.modified = true;
                self.message = Some((message, false));
                self.select_changed(to);
            }
            Err(error) => self.message = Some((error, true)),
        }
        true
    }
}

#[cfg(test)]
impl App {
    /// Waits for the key pair being generated and adds it. Returns whether
    /// one was being generated.
    pub(crate) fn finish_generation(&mut self) -> bool {
        if self.generation.is_none() {
            return false;
        }
        while !self.poll_generation() {
            thread::sleep(std::time::Duration::from_millis(1));
        }
        true
    }
}

/// A new key pair and its chain: the certificate, self-signed or signed by
/// `issuer`, whose chain then follows it.
pub(crate) type Generated = (Key, Vec<Vec<u8>>);

/// Generates a key pair and its certificate; runs off the UI thread.
fn generate(
    algorithm: Algorithm,
    request: &signing::Request,
    signer: Option<Generated>,
) -> Result<Generated, String> {
    let issuer = signer.as_ref().map(|(key, chain)| signing::Issuer {
        key,
        certificate: &chain[0],
    });
    // Without random numbers the search for primes would never end.
    OsRng::default().check()?;
    let mut rng = OsRng::default();
    let key = key_pair(algorithm, &mut rng)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    let certificate = signing::key_certificate(&key, request, issuer.as_ref(), now, &mut rng)?;
    rng.check()?;
    let mut chain = vec![certificate];
    chain.extend(signer.map(|(_, chain)| chain).unwrap_or_default());
    Ok((key, chain))
}

/// A key pair being generated on a background thread. Dropping it, as
/// closing the keystore does, throws its result away.
pub struct Job {
    alias: String,
    algorithm: Algorithm,
    signer: Option<String>,
    started: Instant,
    result: Receiver<Result<Generated, String>>,
}

impl Job {
    /// Runs `work` on a new thread.
    pub(crate) fn start(
        alias: String,
        algorithm: Algorithm,
        signer: Option<String>,
        work: impl FnOnce() -> Result<Generated, String> + Send + 'static,
    ) -> Self {
        let (sender, result) = mpsc::channel();
        thread::spawn(move || {
            // The receiver is gone when the keystore was closed meanwhile.
            let _ = sender.send(work());
        });
        Self {
            alias,
            algorithm,
            signer,
            started: Instant::now(),
            result,
        }
    }

    /// The algorithm, an activity indicator, and the time taken so far: the
    /// library reports no progress to measure.
    fn status(&self) -> String {
        const SPINNER: [char; 4] = ['|', '/', '-', '\\'];
        let elapsed = self.started.elapsed();
        let frame = SPINNER[(elapsed.as_millis() / 125 % 4) as usize];
        format!(
            "{frame} Generating {} key pair '{}'... {}s (read-only until done)",
            self.algorithm.label(),
            self.alias,
            elapsed.as_secs()
        )
    }
}

#[cfg(test)]
mod tests {
    use crown::x509::cert::Certificate;

    use super::*;
    use crate::{
        key_import::matching_chain,
        signing::{Purpose, Subject},
        test_support::TestRng,
    };

    /// Deterministic bytes that vary enough for primes to be found.
    struct Mixed(u64);

    impl Rng for Mixed {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut mixed = self.0;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *byte = (mixed >> 56) as u8;
            }
        }
    }

    fn request() -> signing::Request {
        signing::Request {
            subject: Subject {
                common_name: "generated",
                ..Subject::default()
            }
            .name(),
            days: 1,
            names: Vec::new(),
            purpose: Purpose::None,
        }
    }

    #[test]
    fn every_algorithm_gives_a_key_that_signs_its_own_certificate() {
        // A small RSA key keeps the test fast; the sizes offered work alike.
        let algorithms = [Algorithm::Rsa(1024)]
            .into_iter()
            .chain(Algorithm::ALL.into_iter().skip(3));
        for algorithm in algorithms {
            let mut rng = Mixed(7);
            let key = key_pair(algorithm, &mut rng).unwrap();
            let der = signing::self_signed(&key, &request(), 0, &mut rng).unwrap();
            let parsed = Certificate::parse(&der).unwrap();
            assert_eq!(
                parsed.verify_signature(parsed.public_key()),
                Ok(true),
                "{}",
                algorithm.label()
            );
            let chains = [vec![der]];
            assert_eq!(matching_chain(&key, &chains), Ok(Some(chains[0].clone())));
        }
    }

    #[test]
    fn keys_differ_and_have_the_size_asked_for() {
        let summary = |algorithm, seed| {
            let mut rng = Mixed(seed);
            let key = key_pair(algorithm, &mut rng).unwrap();
            let der = signing::self_signed(&key, &request(), 0, &mut rng).unwrap();
            (key, crate::certificate::summarize(&der).unwrap())
        };
        let (first, rsa) = summary(Algorithm::Rsa(1024), 1);
        assert_eq!((rsa.algorithm.as_str(), rsa.key_size), ("RSA", Some(1024)));
        assert_ne!(first, summary(Algorithm::Rsa(1024), 2).0);
        for (curve, bits) in [
            (CurveId::P256, 256),
            (CurveId::P384, 384),
            (CurveId::P521, 521),
        ] {
            let (_, ec) = summary(Algorithm::Ec(curve), 1);
            assert_eq!((ec.algorithm.as_str(), ec.key_size), ("EC", Some(bits)));
        }
        assert_ne!(
            key_pair(Algorithm::Ed25519, &mut TestRng(1)),
            key_pair(Algorithm::Ed25519, &mut TestRng(2))
        );
        assert_eq!(
            Algorithm::ALL.map(Algorithm::label),
            [
                "RSA 2048", "RSA 3072", "RSA 4096", "EC P-256", "EC P-384", "EC P-521", "Ed25519"
            ]
        );
    }

    #[test]
    fn a_key_that_cannot_be_generated_is_reported() {
        // The library refuses an RSA key this small.
        assert_eq!(
            key_pair(Algorithm::Rsa(128), &mut Mixed(1)),
            Err(NOT_GENERATED.into())
        );
        // Without the recorded candidates, the primes are not found.
        assert!(factor(&Bn::from_u64(15), &[]).is_none());
        assert!(factor(&Bn::from_u64(15), &[Zeroizing::new(Vec::new())]).is_none());
        let seven = [Zeroizing::new(vec![0x07])];
        assert!(factor(&Bn::from_u64(15), &seven).is_none());
    }
}
