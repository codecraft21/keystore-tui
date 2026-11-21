//! Generating a key pair with a certificate, self-signed or signed by
//! another private key of the keystore: the key algorithms, and adding the
//! result to the open keystore once its form is filled in.
use std::{
    fmt::Write as _,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crown::{
    asn1::{
        der,
        oid::{self, ObjectIdentifier},
    },
    bn::{Bn, Montgomery},
    ec::{self, CurveId},
    ecdh,
    rng::Rng,
    rsa::der::rsa_private_key_der,
    x509::keys::encode_ec_private_key,
};
use ratatui::{
    Frame,
    crossterm::event::KeyEvent,
    layout::Constraint,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Clear, Padding, Paragraph, Wrap},
};
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

/// A source of random bytes whose requests can fail.
trait TryRng {
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), String>;
}

impl TryRng for OsRng {
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), String> {
        OsRng::try_fill_bytes(self, out)
    }
}

#[cfg(test)]
struct InfallibleRng<'a, R>(&'a mut R);

#[cfg(test)]
impl<R: Rng> TryRng for InfallibleRng<'_, R> {
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), String> {
        self.0.fill_bytes(out);
        Ok(())
    }
}

/// Adapts a [`TryRng`] to `crown`'s infallible [`Rng`], recording the first
/// error and skipping further draws once it has failed.
struct TryRngAdapter<'a, R> {
    rng: &'a mut R,
    error: Option<String>,
}

impl<R: TryRng> Rng for TryRngAdapter<'_, R> {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        if self.error.is_none()
            && let Err(error) = self.rng.try_fill_bytes(out)
        {
            self.error = Some(error);
        }
    }
}

/// A new private key of this algorithm, as PKCS #8.
#[cfg(test)]
pub fn key_pair(algorithm: Algorithm, rng: &mut impl Rng) -> Result<Key, String> {
    try_key_pair(algorithm, &mut InfallibleRng(rng))
}

fn try_key_pair(algorithm: Algorithm, rng: &mut impl TryRng) -> Result<Key, String> {
    match algorithm {
        Algorithm::Rsa(bits) => rsa(bits, rng),
        Algorithm::Ec(curve) => elliptic(curve, rng),
        Algorithm::Ed25519 => {
            let mut seed = Zeroizing::new([0; 32]);
            rng.try_fill_bytes(&mut *seed)?;
            let key = Zeroizing::new(der::octet_string(&*seed));
            Ok(pkcs8(&der::oid(&object(oid::OID_ED25519)), &key))
        }
    }
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

/// A `crown::bn::Bn` whose limbs are shifted down to zero on drop, since
/// `crown::bn::Bn` does not implement `Zeroize`.
struct ZeroizingBn(Bn);

impl std::ops::Deref for ZeroizingBn {
    type Target = Bn;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingBn {
    fn drop(&mut self) {
        while !self.0.is_zero() {
            self.0.shr1();
        }
        std::hint::black_box(&self.0);
    }
}

fn elliptic(curve: CurveId, rng: &mut impl TryRng) -> Result<Key, String> {
    let arcs = match curve {
        CurveId::P256 => oid::OID_SECP256R1,
        CurveId::P384 => oid::OID_SECP384R1,
        CurveId::P521 => oid::OID_SECP521R1,
    };
    let mut adapter = TryRngAdapter { rng, error: None };
    let result = ecdh::generate(curve, &mut adapter);
    if let Some(error) = adapter.error {
        return Err(error);
    }
    let (scalar, public) = result.map_err(|_| NOT_GENERATED.to_owned())?;
    let scalar = ZeroizingBn(scalar);
    let public = public.to_bytes_with(&ec::curve(curve));
    let key = Zeroizing::new(
        encode_ec_private_key(arcs, &scalar, Some(&public))
            .map_err(|_| NOT_GENERATED.to_owned())?,
    );
    let algorithm = [
        der::oid(&object(oid::OID_EC_PUBLIC_KEY)),
        der::oid(&object(arcs)),
    ]
    .concat();
    Ok(pkcs8(&algorithm, &key))
}

/// Upper bound on prime candidates tested per prime, preventing an infinite
/// loop even if an infallible RNG produces degenerate output.
const MAX_PRIME_CANDIDATES: usize = 100_000;

/// Miller-Rabin rounds per OpenSSL's `bn_mr_min_checks`.
fn mr_rounds(bits: usize) -> usize {
    if bits > 2048 { 128 } else { 64 }
}

/// All primes below 17864 (OpenSSL's trial-division table size).
fn small_primes() -> Vec<u64> {
    const LIMIT: usize = 17864;
    let mut sieve = vec![true; LIMIT];
    let mut out = Vec::with_capacity(2262);
    for i in 2..LIMIT {
        if sieve[i] {
            out.push(i as u64);
            let mut j = i * i;
            while j < LIMIT {
                sieve[j] = false;
                j += i;
            }
        }
    }
    out
}

/// Miller-Rabin probabilistic primality test (FIPS 186-4 C.3.1), aborting
/// immediately if `rng` fails.
fn is_probable_prime(n: &Bn, rounds: usize, rng: &mut impl TryRng) -> Result<bool, String> {
    if n.lt(&Bn::from_u64(3)) || n.is_even() {
        return Ok(false);
    }

    let one = Bn::one();
    let two = Bn::from_u64(2);
    let n1 = ZeroizingBn(n.sub(&one).map_err(|_| NOT_GENERATED.to_owned())?);
    let mut s = 0usize;
    let mut d = ZeroizingBn((*n1).clone());
    while d.is_even() {
        d.0.shr1();
        s += 1;
    }
    // Witness range: [2, n - 2].
    let range = ZeroizingBn(
        n1.sub(&one)
            .and_then(|v| v.sub(&one))
            .map_err(|_| NOT_GENERATED.to_owned())?,
    );

    let mont = Montgomery::new(n).map_err(|_| NOT_GENERATED.to_owned())?;
    let one_m = mont.to_mont(&one);
    let n1_m = mont.to_mont(&n1);

    let mut buf = vec![0u8; n.byte_len() + 8];
    'rounds: for _ in 0..rounds {
        rng.try_fill_bytes(&mut buf)?;
        let witness = Bn::from_be_bytes(&buf).modulus(&range).add(&two);

        let mut x = mont.pow(&mont.to_mont(&witness), &d);
        if x == one_m || x == n1_m {
            continue;
        }
        for _ in 0..s.saturating_sub(1) {
            x = mont.mul(&x, &x);
            if x == n1_m {
                continue 'rounds;
            }
            if x == one_m {
                return Ok(false);
            }
        }
        return Ok(false);
    }
    Ok(true)
}

/// Generates a `bits`-bit probable prime with its top two bits set, odd, and
/// coprime to `e`, aborting immediately if `rng` fails.
fn generate_prime(
    bits: usize,
    e: u64,
    primes: &[u64],
    rng: &mut impl TryRng,
) -> Result<ZeroizingBn, String> {
    let one = Bn::one();
    let mut bytes = Zeroizing::new(vec![0u8; bits.div_ceil(8)]);
    let extra = bytes.len() * 8 - bits;
    for _ in 0..MAX_PRIME_CANDIDATES {
        rng.try_fill_bytes(&mut bytes)?;
        if extra > 0 {
            bytes[0] &= 0xff >> extra;
        }
        bytes[0] |= 0xc0 >> extra;
        if extra == 7 {
            bytes[1] |= 0x80;
        }
        *bytes.last_mut().unwrap() |= 1;
        let cand = Bn::from_be_bytes(&bytes);

        let cand1 = cand.sub(&one).map_err(|_| NOT_GENERATED.to_owned())?;
        if cand1.rem_small(e) == 0 {
            continue;
        }

        if primes.iter().any(|&p| cand.rem_small(p) == 0) {
            continue;
        }

        if is_probable_prime(&cand, mr_rounds(bits), rng)? {
            return Ok(ZeroizingBn(cand));
        }
    }
    Err(NOT_GENERATED.into())
}

/// An RSA key of `bits` bits with the public exponent 65537.
///
/// Primes are generated directly with `crown::bn` so RNG failures abort
/// immediately and secret big-integer values are wiped on drop.
fn rsa(bits: usize, rng: &mut impl TryRng) -> Result<Key, String> {
    const EXPONENT: u64 = 65537;
    if bits < 512 || !bits.is_multiple_of(2) {
        return Err(NOT_GENERATED.into());
    }
    let half = bits / 2;
    let primes = small_primes();
    let p = generate_prime(half, EXPONENT, &primes, rng)?;
    // FIPS 186-4 B.3.3: |p - q| must be large.
    let mut q = None;
    for _ in 0..16 {
        let candidate = generate_prime(half, EXPONENT, &primes, rng)?;
        let (lo, hi) = if p.lt(&candidate) {
            (&*p, &*candidate)
        } else {
            (&*candidate, &*p)
        };
        let diff = hi.sub(lo).map_err(|_| NOT_GENERATED.to_owned())?;
        if diff.bit_len() >= half - 100 {
            q = Some(candidate);
            break;
        }
    }
    let q = q.ok_or_else(|| NOT_GENERATED.to_owned())?;
    let (p, q) = if p.lt(&q) { (q, p) } else { (p, q) };

    let modulus = p.mul(&q);
    let one = Bn::one();
    let p1 = ZeroizingBn(p.sub(&one).map_err(|_| NOT_GENERATED.to_owned())?);
    let q1 = ZeroizingBn(q.sub(&one).map_err(|_| NOT_GENERATED.to_owned())?);
    let exponent = Bn::from_u64(EXPONENT);
    let phi = ZeroizingBn(p1.mul(&q1));
    let d = ZeroizingBn(
        exponent
            .mod_inverse(&phi)
            .map_err(|_| NOT_GENERATED.to_owned())?,
    );
    let qinv = ZeroizingBn(q.mod_inverse(&p).map_err(|_| NOT_GENERATED.to_owned())?);
    let bytes = |number: &Bn| Zeroizing::new(number.to_be_bytes());
    let key = Zeroizing::new(rsa_private_key_der(
        &modulus.to_be_bytes(),
        &exponent.to_be_bytes(),
        &bytes(&d),
        &bytes(&p),
        &bytes(&q),
        &bytes(&ZeroizingBn(d.modulus(&p1))),
        &bytes(&ZeroizingBn(d.modulus(&q1))),
        &bytes(&qinv),
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
        if self.editable() {
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
    /// on a worker thread. A modal waits for it.
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

    /// Cancels the key pair being generated: its thread is left to finish,
    /// and the key it makes is wiped when the result finds no receiver.
    pub(crate) fn cancel_generation(&mut self) {
        if let Some(job) = self.generation.take() {
            let message = format!(
                "Generating {} key pair '{}' was cancelled.",
                job.algorithm.label(),
                job.alias
            );
            self.message = Some((message, false));
        }
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
                    write!(message, ", signed by '{signer}'").unwrap();
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
    let key = try_key_pair(algorithm, &mut rng)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64);
    let certificate = signing::key_certificate(&key, request, issuer.as_ref(), now, &mut rng)?;
    rng.check()?;
    let mut chain = vec![certificate];
    chain.extend(signer.map(|(_, chain)| chain).unwrap_or_default());
    Ok((key, chain))
}

/// The keys that work while a key pair is generated.
pub const SHORTCUTS: &str = "Esc Cancel | Ctrl+C Quit";

/// A key pair being generated on a worker thread. Dropping it, as
/// cancelling or closing the keystore does, throws its result away.
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
            // Without a receiver, as after cancelling, the result is handed
            // back and dropped here, which wipes the key.
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
            "{frame} Generating {} key pair '{}'... {}s",
            self.algorithm.label(),
            self.alias,
            elapsed.as_secs()
        )
    }

    /// Draws the modal that waits for the key pair over the middle of the
    /// main view.
    pub(crate) fn draw(&self, frame: &mut Frame) {
        let status = self.status();
        let screen = frame.area();
        let width = (status.chars().count().max(SHORTCUTS.len()) + 4) as u16;
        let area = screen.centered(
            Constraint::Length(width.min(screen.width)),
            Constraint::Length(MODAL_HEIGHT.min(screen.height)),
        );
        let block = Block::bordered().title(" Generate key pair ");
        let inner = block.inner(area);
        frame.render_widget(Clear, area);
        frame.render_widget(block, area);
        let text = vec![
            Line::styled(status, Style::default().fg(Color::Cyan)),
            Line::default(),
            Line::from(SHORTCUTS),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(Block::new().padding(Padding::horizontal(1))),
            inner,
        );
    }
}

/// The modal's height: its three lines inside the border.
const MODAL_HEIGHT: u16 = 5;

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
        // Keys smaller than 512 bits or with an odd bit length are refused.
        assert_eq!(
            key_pair(Algorithm::Rsa(128), &mut Mixed(1)),
            Err(NOT_GENERATED.into())
        );
        assert_eq!(
            key_pair(Algorithm::Rsa(1025), &mut Mixed(1)),
            Err(NOT_GENERATED.into())
        );
    }

    struct FailingRng {
        inner: Mixed,
        fail_after: usize,
        calls: usize,
    }

    impl FailingRng {
        fn new(seed: u64, fail_after: usize) -> Self {
            Self {
                inner: Mixed(seed),
                fail_after,
                calls: 0,
            }
        }
    }

    impl TryRng for FailingRng {
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), String> {
            let call = self.calls;
            self.calls += 1;
            if call >= self.fail_after {
                return Err("rng failed".into());
            }
            self.inner.fill_bytes(out);
            Ok(())
        }
    }

    #[test]
    fn rsa_generation_aborts_immediately_on_mid_generation_rng_failure() {
        for algorithm in [Algorithm::Rsa(2048), Algorithm::Rsa(3072)] {
            for fail_after in [0, 1, 2, 5, 10] {
                let mut rng = FailingRng::new(7, fail_after);
                assert_eq!(
                    try_key_pair(algorithm, &mut rng),
                    Err("rng failed".into()),
                    "{} failing after {fail_after} draws",
                    algorithm.label()
                );
                assert_eq!(
                    rng.calls,
                    fail_after + 1,
                    "{} should stop on the failing draw",
                    algorithm.label()
                );
            }
        }

        // Count how many draws a complete RSA-1024 generation needs, then fail
        // at several points across both primes and their Miller-Rabin rounds.
        let mut counter = FailingRng::new(7, usize::MAX);
        try_key_pair(Algorithm::Rsa(1024), &mut counter).unwrap();
        let total_draws = counter.calls;
        assert!(total_draws > 128);
        for fail_after in [0, 1, 2, total_draws / 4, total_draws / 2, total_draws - 1] {
            let mut rng = FailingRng::new(7, fail_after);
            assert_eq!(
                try_key_pair(Algorithm::Rsa(1024), &mut rng),
                Err("rng failed".into()),
                "RSA 1024 failing after {fail_after} of {total_draws} draws"
            );
            assert_eq!(rng.calls, fail_after + 1);
        }
    }

    #[test]
    fn ec_and_ed25519_generation_propagate_rng_failure() {
        for algorithm in [Algorithm::Ec(CurveId::P256), Algorithm::Ed25519] {
            let mut rng = FailingRng::new(7, 0);
            assert_eq!(
                try_key_pair(algorithm, &mut rng),
                Err("rng failed".into()),
                "{}",
                algorithm.label()
            );
            assert_eq!(rng.calls, 1);
        }
    }

    #[test]
    fn rsa_generation_terminates_when_infallible_rng_returns_zeros() {
        struct ZeroRng;
        impl Rng for ZeroRng {
            fn fill_bytes(&mut self, _: &mut [u8]) {}
        }

        for algorithm in [Algorithm::Rsa(2048), Algorithm::Rsa(3072)] {
            assert_eq!(
                key_pair(algorithm, &mut ZeroRng),
                Err(NOT_GENERATED.into()),
                "{}",
                algorithm.label()
            );
        }
    }

    #[test]
    fn zeroizing_bn_shifts_multi_limb_values_to_zero() {
        let mut scalar = ZeroizingBn(Bn::from_be_bytes(&[0xff; 66]));
        assert!(!scalar.is_zero());
        while !scalar.0.is_zero() {
            scalar.0.shr1();
        }
        assert!(scalar.is_zero());
        drop(scalar);
        drop(ZeroizingBn(Bn::zero()));
    }

    #[test]
    fn offered_rsa_sizes_produce_valid_keys_of_the_requested_size() {
        for bits in [2048, 3072, 4096] {
            let algorithm = Algorithm::Rsa(bits);
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
            let summary = crate::certificate::summarize(&der).unwrap();
            assert_eq!(
                (summary.algorithm.as_str(), summary.key_size),
                ("RSA", Some(bits as u32)),
                "{}",
                algorithm.label()
            );
            let chains = [vec![der]];
            assert_eq!(matching_chain(&key, &chains), Ok(Some(chains[0].clone())));
        }
    }
}
