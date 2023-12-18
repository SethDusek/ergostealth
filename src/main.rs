use std::io::{BufRead, Write};

use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
use ergo_lib::wallet::tx_builder::TxBuilder;
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
use serde_json::json;

// Convert transaction into JSON for /wallet/transaction/sign
fn encode_transaction(unsigned_tx: &UnsignedTransaction, boxes_to_spend: &[ErgoBox]) {
    fn encode_boxes(maybe_boxes: Option<&[ErgoBox]>) -> Option<Vec<String>> {
        maybe_boxes.map(|boxes| {
            boxes
                .iter()
                .map(|b| {
                    b.sigma_serialize_bytes()
                        .map(|bytes| base16::encode_lower(&bytes))
                        .unwrap()
                })
                .collect::<Vec<String>>()
        })
    }

    let input_boxes_base16 = encode_boxes(Some(boxes_to_spend));

    let prepared_body = json!({
        "tx": unsigned_tx,
        "inputsRaw": input_boxes_base16,
        "dataInputsRaw": [],
    });
    println!("{}", prepared_body);
}
fn mint_token(node_interface: &NodeInterface) -> Result<Token, Box<dyn std::error::Error>> {
    let addr = &node_interface.wallet_addresses()?[0];
    let addr = AddressEncoder::new(NetworkPrefix::Testnet).parse_address_from_str(&addr)?;
    let block_height = node_interface.current_block_height()?;

    let utxos = node_interface.unspent_boxes()?;
    let box_selector = SimpleBoxSelector::new();
    let selection = box_selector.select(
        utxos,
        BoxValue::new(BoxValue::SAFE_USER_MIN.as_u64() * 2)?,
        &[],
    )?;
    let mut output_box =
        ErgoBoxCandidateBuilder::new(BoxValue::SAFE_USER_MIN, addr.script()?, block_height as u32);
    let token = Token {
        token_id: selection.boxes.first().box_id().into(),
        amount: TokenAmount::MAX_RAW.try_into()?,
    };
    output_box.mint_token(
        token.clone(),
        "Test".to_string(),
        "Testing Token".to_string(),
        1,
    );

    let tx = TxBuilder::new(
        selection.clone(),
        vec![output_box.build()?],
        block_height.try_into().unwrap(),
        BoxValue::SAFE_USER_MIN,
        addr,
    );

    let unsigned_tx = tx.build()?;
    println!(
        "Minting Token {:?}",
        unsigned_tx
            .output_candidates
            .first()
            .tokens
            .as_ref()
            .unwrap()
    );
    encode_transaction(&unsigned_tx, selection.boxes.as_slice());
    Ok(token)
}
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
fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    mint_token(&node_interface)?;
    Ok(())
}
