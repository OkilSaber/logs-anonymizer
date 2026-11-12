//! Templates d'anonymisation : modèle TOML, héritage, bibliothèque, tests embarqués.
//!
//! Un template est déclaratif : il nomme et configure les briques du moteur, il ne
//! contient jamais de code.

pub mod library;
pub mod model;
pub mod testing;

pub const SCHEMA_VERSION: u32 = 1;
