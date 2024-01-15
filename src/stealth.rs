use ergo_lib::{
    ergo_chain_types::{
        blake2b256_hash,
        ec_point::{exponentiate, generator},
        EcPoint,
    },
    ergotree_interpreter::sigma_protocol::private_input::DlogProverInput,
    ergotree_ir::{
        chain::address::{Address, AddressEncoder, NetworkPrefix},
        sigma_protocol::sigma_boolean::ProveDlog,
    },
    wallet::{secret_key::SecretKey, signing::ErgoTransaction, tx_context::TransactionContext},
};
use k256::{elliptic_curve::PrimeField, FieldBytes, Scalar};
use sigma_ser::ScorexSerializable;

// Build a silent payment public key that can be recovered by receiver
pub fn build_stealth_payment_address(sender_sk: &SecretKey, receiver_pk: &ProveDlog) -> ProveDlog {
    if let SecretKey::DlogSecretKey(DlogProverInput { w }) = sender_sk {
        let s: Scalar = w.clone().into();
        // Compute s * r * G using sender's private key (s) and receiver's public key ( r * G )
        // Receiver can recover s * r * G by using their private key (r) and sender's public key s * G
        let shared_secret: EcPoint = exponentiate(&receiver_pk.h, &s);
        // Compute hash(s * r * G) to prevent potential rogue key attacks. For example imagine a malicious sender computes s such that s * r * G + r * G == c * G where sender knows the secret c
        let hashpk = blake2b256_hash(&shared_secret.scorex_serialize_bytes().unwrap());
        // Convert hash into a scalar
        let hashpk = Scalar::from_repr(*FieldBytes::from_slice(&hashpk.0[..])).unwrap();

        // In elliptic curve terms here we're computing Hash(rsG) + R where R is receiver public key (rG). rsg == sR == rS. Thus both receiver and sender can compute the same shared secret
        let pk = exponentiate(&generator(), &hashpk) * &receiver_pk.h;
        ProveDlog { h: Box::new(pk) }
    } else {
        panic!("Expected ProveDlog secret key, found DhtSecretKey");
    }
}

// Detects a silent payment from a transaction. Currently only works with transactions with 1 input and the 1st output must be receiver's stealth address
pub fn detect_silent_payment<T: ErgoTransaction + serde::Serialize>(
    receiver_sk: &DlogProverInput,
    tx_context: TransactionContext<T>,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string(&tx_context.spending_tx)?);
    let output_pk =
        Address::recreate_from_ergo_tree(&tx_context.spending_tx.outputs().first().ergo_tree)?;
    let sender_box = tx_context.spending_tx.inputs_ids().first().clone();
    let sender_box = tx_context.get_input_box(&sender_box).ok_or(format!(
        "Can't find input box {} in transaction context",
        sender_box.to_string()
    ))?;
    let sender_pk = Address::recreate_from_ergo_tree(&sender_box.ergo_tree)?;
    if let (Address::P2Pk(sender_pk), Address::P2Pk(stealth_address)) =
        (sender_pk, output_pk.clone())
    {
        let shared_secret: EcPoint = exponentiate(&sender_pk.h, &receiver_sk.w.clone().into());
        let hashpk = blake2b256_hash(&shared_secret.scorex_serialize_bytes()?);
        // Convert hash into a scalar
        let hashpk = Scalar::from_repr(*FieldBytes::from_slice(&hashpk.0[..])).unwrap();
        // The public key is hash(s * r * G)G + rG. Thus the private key is hash(s * r * G) + r
        let stealth_private_key = hashpk + receiver_sk.w.as_scalar_ref();

        let stealth_public_key = exponentiate(&generator(), &stealth_private_key);
        if stealth_public_key != *stealth_address.h {
            let stealth_address = AddressEncoder::new(NetworkPrefix::Testnet)
                .address_to_str(&Address::P2Pk(ProveDlog::new(stealth_public_key)));
            let output_address =
                AddressEncoder::new(NetworkPrefix::Testnet).address_to_str(&output_pk);
            return Err(format!(
                "Did not detect stealth payment, output address: {}, computed stealth address: {}",
                output_address, stealth_address
            ))?;
        }
        Ok(SecretKey::DlogSecretKey(DlogProverInput {
            w: stealth_private_key.into(),
        }))
    } else {
        return Err("Expected Two Dlog secret keys")?;
    }
}
