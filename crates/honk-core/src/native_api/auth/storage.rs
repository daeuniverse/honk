//! Durable administrator records.

use std::sync::Arc;

use base64::Engine as _;
use parking_lot::Mutex;
use rand::Rng as _;
use rusqlite::{OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{BASE64, PBKDF2_ITERATIONS, pbkdf2_sha256, valid_password, valid_username};
use crate::state::StateDb;

const ITERATIONS_RANGE: std::ops::RangeInclusive<u32> = 100_000..=1_000_000;

/// The stored administrator: everything needed to verify a login, nothing that reveals the password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) username: String,
    pub(crate) iterations: u32,
    pub(crate) salt: [u8; 16],
    pub(crate) hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: u32,
    username: String,
    algorithm: String,
    iterations: u32,
    salt: String,
    hash: String,
}

impl Record {
    pub(crate) fn create(username: &str, password: &str) -> Option<Self> {
        if !valid_username(username) || !valid_password(password) {
            return None;
        }
        let mut salt = [0u8; 16];
        rand::rng().fill_bytes(&mut salt);
        Some(Self {
            username: username.to_owned(),
            iterations: PBKDF2_ITERATIONS,
            salt,
            hash: pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS),
        })
    }

    /// Always runs the full derivation, so a wrong username costs the same as a wrong password.
    pub(crate) fn verify(&self, username: &str, password: &str) -> bool {
        let expected: [u8; 32] = Sha256::digest(self.username.as_bytes()).into();
        let given: [u8; 32] = Sha256::digest(username.as_bytes()).into();
        let name_ok = expected.ct_eq(&given);
        let derived = pbkdf2_sha256(password.as_bytes(), &self.salt, self.iterations);
        bool::from(name_ok & derived.ct_eq(&self.hash))
    }

    pub(super) fn to_json(&self) -> Vec<u8> {
        let file = RecordFile {
            version: 1,
            username: self.username.clone(),
            algorithm: "pbkdf2-hmac-sha256".to_owned(),
            iterations: self.iterations,
            salt: BASE64.encode(self.salt),
            hash: BASE64.encode(self.hash),
        };
        let mut json = serde_json::to_vec(&file).expect("record serialises");
        json.push(b'\n');
        json
    }

    pub(super) fn from_json(bytes: &[u8]) -> Result<Self, StoreError> {
        let file: RecordFile = serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
        if file.version != 1
            || file.algorithm != "pbkdf2-hmac-sha256"
            || !ITERATIONS_RANGE.contains(&file.iterations)
            || !valid_username(&file.username)
        {
            return Err(StoreError::Corrupt);
        }
        let salt = BASE64.decode(&file.salt).map_err(|_| StoreError::Corrupt)?;
        let hash = BASE64.decode(&file.hash).map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            username: file.username,
            iterations: file.iterations,
            salt: salt.try_into().map_err(|_| StoreError::Corrupt)?,
            hash: hash.try_into().map_err(|_| StoreError::Corrupt)?,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum StoreError {
    #[error("credential store is unusable: {0}")]
    Unavailable(&'static str),
    #[error("credential record is corrupt or unsupported")]
    Corrupt,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SetupError {
    #[error("an administrator already exists")]
    AlreadyCompleted,
    #[error("the record could not be written")]
    Unavailable,
    /// The row may or may not be durable; nothing may rely on it until a restart.
    #[error("the record was written but not confirmed durable")]
    NotDurable,
}

/// The administrator record in the state db's `admin` row.
pub(crate) struct CredentialStore {
    db: Arc<StateDb>,
    state: Mutex<StoreState>,
}

enum StoreState {
    Uninitialized,
    Ready(Arc<Record>),
    Indeterminate,
}

impl CredentialStore {
    /// Reads the record if present. A record that fails its checks fails
    /// closed. Call with the instance lock held.
    pub(crate) fn open(db: Arc<StateDb>) -> Result<Self, StoreError> {
        let record: Option<String> = db
            .strict()
            .query_row("SELECT record FROM admin WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| StoreError::Unavailable("state db"))?;
        let record = record
            .map(|record| Record::from_json(record.as_bytes()))
            .transpose()?;
        Ok(Self {
            db,
            state: Mutex::new(record.map_or(StoreState::Uninitialized, |record| {
                StoreState::Ready(Arc::new(record))
            })),
        })
    }

    pub(crate) fn setup_required(&self) -> bool {
        matches!(*self.state.lock(), StoreState::Uninitialized)
    }

    /// Verifies a login only against a confirmed durable record.
    pub(crate) fn verify(&self, username: &str, password: &str) -> bool {
        let record = {
            let state = self.state.lock();
            let StoreState::Ready(record) = &*state else {
                return false;
            };
            Arc::clone(record)
        };
        record.verify(username, password)
    }

    /// Publishes the first administrator without replacing anything: a second creator, racing or
    /// not, in this process or another, sees `AlreadyCompleted`.
    pub(crate) fn setup(&self, username: &str, password: &str) -> Result<(), SetupError> {
        let record = Record::create(username, password).ok_or(SetupError::Unavailable)?;
        {
            let mut state = self.state.lock();
            if !matches!(*state, StoreState::Uninitialized) {
                return Err(SetupError::AlreadyCompleted);
            }
            *state = StoreState::Indeterminate;
        }
        let json = String::from_utf8(record.to_json()).map_err(|_| SetupError::Unavailable)?;
        let mut connection = self.db.strict();
        // Nothing is written yet if the transaction cannot start, for example while busy.
        let Ok(transaction) = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        else {
            *self.state.lock() = StoreState::Uninitialized;
            return Err(SetupError::Unavailable);
        };
        // The flag says whether a rollback confirmed that nothing was written.
        let result = (move || {
            if let Err(error) =
                transaction.execute("INSERT INTO admin (id, record) VALUES (1, ?1)", [&json])
            {
                return Err((error, transaction.rollback().is_ok()));
            }
            transaction.commit().map_err(|error| (error, false))
        })();
        match result {
            Ok(()) => {
                *self.state.lock() = StoreState::Ready(Arc::new(record));
                Ok(())
            }
            Err((error, _))
                if error.sqlite_error().is_some_and(|error| {
                    error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                }) =>
            {
                Err(SetupError::AlreadyCompleted)
            }
            Err((_, true)) => {
                *self.state.lock() = StoreState::Uninitialized;
                Err(SetupError::Unavailable)
            }
            // A failed COMMIT leaves the row's durability unknown.
            Err((_, false)) => Err(SetupError::NotDurable),
        }
    }
}
