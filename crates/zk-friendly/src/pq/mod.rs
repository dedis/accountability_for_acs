//! The post-quantum credential model (`pq` feature): the same statement as
//! the post-quantum credential proof of the standard stack
//! (`third_party/longfellow-zk/lib/circuits/tests/pq/credential`), with
//! SHAKE256 in place of Poseidon and SHA-256, the signature chosen at compile
//! time ([`pqc::sig::Selected`]) in place of EdDSA, and threshold Module-LWE
//! encryption ([`pqc::lwe`]) in place of ElGamal. No proof system proves it
//! here yet.

pub mod credential;
pub mod merkle;
pub mod revocation;
