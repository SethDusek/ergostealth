use std::io::{BufRead, Write};
use std::path::Path;
use std::str::FromStr;

use ergo_lib::chain::ergo_state_context::ErgoStateContext;
use ergo_lib::chain::transaction::Transaction;
use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::ergo_chain_types::ec_point::{exponentiate, generator};
use ergo_lib::ergo_chain_types::{blake2b256_hash, EcPoint, Header, PreHeader};
use ergo_lib::ergotree_ir::chain::address::Address;
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog;
use ergo_lib::wallet::derivation_path::DerivationPath;
use ergo_lib::wallet::ext_secret_key::ExtSecretKey;
use ergo_lib::wallet::mnemonic::{Mnemonic, MnemonicSeed};
use ergo_lib::wallet::mnemonic_generator::MnemonicGenerator;
use ergo_lib::wallet::secret_key::SecretKey;
use ergo_lib::wallet::signing::ErgoTransaction;
use ergo_lib::wallet::tx_builder::TxBuilder;
use ergo_lib::wallet::tx_context::{TransactionContext, self};
use ergo_lib::wallet::Wallet;
use ergo_lib::{
    chain::ergo_box::box_builder::ErgoBoxCandidateBuilder,
    ergotree_ir::chain::{
        address::{AddressEncoder, NetworkPrefix},
        ergo_box::box_value::BoxValue,
        token::{Token, TokenAmount},
    },
    wallet::box_selector::{BoxSelector, SimpleBoxSelector},
};
use ergo_node_interface::NodeInterface;
use ergo_node_interface::scanning::NodeError;
use ergostealth::indexer::get_boxes_by_address;
use ergostealth::stealth::{build_stealth_payment_address, detect_silent_payment};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use serde_json::json;
use sigma_ser::ScorexSerializable;

fn read_line(
    line: &mut String,
    stdin: &mut std::io::StdinLock,
    prompt: &str,
) -> Result<(), std::io::Error> {
    print!("{}: ", prompt);
    std::io::stdout().flush()?;
    stdin.read_line(line)?;
    Ok(())
}

fn load_state_context_from_node(
    node_interface: &NodeInterface,
) -> Result<ErgoStateContext, Box<dyn std::error::Error>> {
    let cur_block_height = node_interface.current_block_height()?;
    let headers: Vec<Header> = serde_json::from_str(
        &node_interface
            .send_get_req(&format!(
                "/blocks/chainSlice?fromHeight={}&toHeight={}",
                cur_block_height - 10,
                cur_block_height
            ))?
            .text()?,
    )?;
    let pre_header = headers.last().cloned().unwrap().into();

    Ok(ErgoStateContext::new(
        pre_header,
        headers.try_into().unwrap(),
    ))
}

// Wait for a new block. A more robust mechanism would be to wait for the transaction to be confirmed
fn wait_for_new_block(node_interface: &NodeInterface) -> Result<(), NodeError> {
    let cur_height = node_interface.current_block_height()?;
    while cur_height == node_interface.current_block_height()? {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Ok(())
}

fn pay_to_address(
    node_interface: &NodeInterface,
    sender_pk: Address,
    receiver_pk: Address,
    amount: BoxValue,
) -> Result<TransactionContext<UnsignedTransaction>, Box<dyn std::error::Error>> {
    let utxos = get_boxes_by_address(node_interface, &sender_pk)?;
    let block_height = node_interface.current_block_height()? as u32;
    let box_selector = SimpleBoxSelector::new();
    let selection =
        box_selector.select(utxos, amount.checked_add(&BoxValue::SAFE_USER_MIN)?, &[])?;
    let stealth_address = receiver_pk;
    let output_box = ErgoBoxCandidateBuilder::new(
        amount,
        stealth_address.script()?,
        block_height as u32,
    )
    .build()?;

    let tx = TxBuilder::new(
        selection.clone(),
        vec![output_box],
        block_height,
        BoxValue::SAFE_USER_MIN,
        sender_pk,
    )
    .build()?;
    let tx_context = TransactionContext::new(tx, selection.boxes.clone().to_vec(), vec![])?;
    Ok(tx_context)
}

fn pay_to_stealth_address(
    node_interface: &NodeInterface,
    amount: BoxValue,
    sender_sk: &SecretKey,
    receiver_pk: &ProveDlog,
) -> Result<TransactionContext<UnsignedTransaction>, Box<dyn std::error::Error>> {
    let sender_pk = sender_sk.get_address_from_public_image();
    let utxos = get_boxes_by_address(node_interface, &sender_pk)?;
    dbg!(&utxos);
    if utxos.len() == 0 {
        println!(
            "The sender's address must be topped up with 1.001 ERG. Please send 1.001 ERG to {}",
            AddressEncoder::new(NetworkPrefix::Testnet).address_to_str(&sender_pk)
        );
    }
    let stealth_address = Address::P2Pk(build_stealth_payment_address(sender_sk, receiver_pk));
    pay_to_address(node_interface, sender_pk, stealth_address, amount)
}

// Load mnemonic from file or create new mnemonic
fn load_sk_from_file<P: AsRef<Path>>(path: P) -> Result<ExtSecretKey, Box<dyn std::error::Error>> {
    let path = path.as_ref();
    let mnemonic = if path.exists() {
        Mnemonic::to_seed(&std::fs::read_to_string(path)?, "")
    } else {
        let mnemonic_phrase =
            MnemonicGenerator::new(ergo_lib::wallet::mnemonic_generator::Language::English, 256)
                .generate()?;
        std::fs::write(path, &mnemonic_phrase)?;
        println!(
            "Mnemonic not found. Created new mnemonic at {}",
            path.display()
        );
        Mnemonic::to_seed(&mnemonic_phrase, "")
    };
    Ok(ExtSecretKey::derive_master(mnemonic)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ext_sk = load_sk_from_file("sender.sk")?;
    // let ext_sk = ExtSecretKey::derive_master(seed)?
    //     .derive(DerivationPath::from_str("m/44'/429'/0'/0/0")?)?;
    println!(
        "Sender Address: {}",
        AddressEncoder::new(NetworkPrefix::Testnet).address_to_str(
            &ergo_lib::ergotree_ir::chain::address::Address::P2Pk(ext_sk.public_image())
        )
    );
    let receiver_sk = load_sk_from_file("receiver.sk")?;
    let receiver_pk = receiver_sk.public_image();
    println!(
        "Receiver Address: {}",
        AddressEncoder::new(NetworkPrefix::Testnet).address_to_str(
            &ergo_lib::ergotree_ir::chain::address::Address::P2Pk(receiver_pk.clone())
        )
    );

    // Compute stealth address
    let stealth_address = build_stealth_payment_address(&ext_sk.secret_key(), &receiver_pk);
    println!(
        "Computed Stealth Address: {}",
        AddressEncoder::new(NetworkPrefix::Testnet).address_to_str(
            &ergo_lib::ergotree_ir::chain::address::Address::P2Pk(stealth_address.clone())
        )
    );

    let mut line = String::new();
    let mut stdin = std::io::stdin().lock();

    read_line(&mut line, &mut stdin, "Enter node ip:port")?;
    let (ip, port) = line
        .trim_end()
        .split_once(":")
        .expect("Failed to parse ip address:port");

    let mut line = String::new();
    read_line(&mut line, &mut stdin, "Enter API key")?;
    let node_interface = NodeInterface::new(line.trim_end(), ip, port)?;

    let tx_context = pay_to_stealth_address(
        &node_interface,
        BoxValue::new(BoxValue::UNITS_PER_ERGO as u64)?,
        &ext_sk.secret_key(),
        &receiver_pk,
    )?;
    let receiver_sk = if let SecretKey::DlogSecretKey(sk) = receiver_sk.secret_key() {
        sk
    } else {
        unreachable!()
    };
    // // // Sender will now sign and broadcast his transaction paying to the stealth address. Receiver will check the transaction for a stealth payment and calculate their secret key needed to spend
    let wallet = Wallet::from_secrets(vec![ext_sk.secret_key()]);
    let state_context = load_state_context_from_node(&node_interface)?;

    let signed = wallet.sign_transaction(tx_context.clone(), &state_context, None)?;
    node_interface.submit_transaction(&signed).unwrap();
    println!("TX submitted {}. Waiting for confirmation", signed.id());
    wait_for_new_block(&node_interface)?;

    let res = detect_silent_payment(&receiver_sk, tx_context)?;
    // println!("Stealth payment detected from TX {}!", signed.id());
    let stealth_wallet = Wallet::from_secrets(vec![res.clone()]);

    // Send back stealth coins to my own address for convenience.
    let send_back_address = AddressEncoder::new(NetworkPrefix::Testnet)
        .parse_address_from_str("3WwkxVkCiN5PKa4CLg72aX2XR53QfGRZmfJxEgiQEqsMmi59ULwq")?;
    let send_back_tx = pay_to_address(
        &node_interface,
        res.get_address_from_public_image(),
        send_back_address,
        BoxValue::new(BoxValue::UNITS_PER_ERGO as u64)?.checked_sub(&BoxValue::SAFE_USER_MIN)?,
    )?;

    let signed_tx = stealth_wallet.sign_transaction(send_back_tx, &state_context, None)?;
    node_interface.submit_transaction(&signed_tx)?;
    Ok(())
}
