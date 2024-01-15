use ergo_lib::ergotree_ir::chain::{
    address::{Address, AddressEncoder},
    ergo_box::ErgoBox,
};
use ergo_node_interface::{scanning::NodeError, NodeInterface};

// Get boxes by address. Requires node's extra indexer to be enabled
pub fn get_boxes_by_address(
    node_interface: &NodeInterface,
    address: &Address,
) -> Result<Vec<ErgoBox>, NodeError> {
    // TODO: change this based on which node type is connected
    let addr_str =
        AddressEncoder::new(ergo_lib::ergotree_ir::chain::address::NetworkPrefix::Testnet)
            .address_to_str(address);
    // TODO: should probably do 2 api calls, one with limit=0 to find total number of boxes, and another to fetch boxes
    let res_json = node_interface.parse_response_to_json(
        node_interface.send_post_req("/blockchain/box/unspent/byAddress?offset=0&limit=10000", addr_str),
    )?;
    let mut box_list = vec![];
    for i in 0.. {
        let box_json = &res_json[i];
        if box_json.is_null() {
            break;
        } else if let Ok(ergo_box) = serde_json::from_str(&box_json.to_string()) {
            box_list.push(ergo_box);
        }
    }
    Ok(box_list)
}
