use k256::ecdsa::SigningKey;
// use rand_core::OsRng;
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;

fn main() {
    // // For Generating Random Secret Key
    // let secret_key = SigningKey::random(&mut OsRng);
    let secret_key = SigningKey::from_slice(
        &hex::decode("dcecedeed3e13fe0c0bc3e5424442c2b58be35578d8df47e17296d5d579a0bbf").unwrap(),
    )
    .unwrap();
    let pubkey_coordinates = secret_key.verifying_key().to_encoded_point(false);
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let message: &[u8] = b"tempData";
    let pi = vrf.prove(&secret_key.to_bytes(), &message).unwrap();
    // Note:- Decode VRF Proof Using `decodeProof` Method Of `VRF` Contract And Then Pass Received Uint256 Form Proof In Verify Method.
    println!(
        "PubKey X And Y: [{:?}, {:?}] \nProof: 0x{} \nMessage: 0x{}",
        format!("0x{}", hex::encode(pubkey_coordinates.x().unwrap())),
        format!("0x{}", hex::encode(pubkey_coordinates.y().unwrap())),
        hex::encode(&pi),
        hex::encode(message)
    );
    println!(
        "VRF Hash: 0x{}",
        hex::encode(vrf.proof_to_hash(&pi).unwrap())
    );
    let vrf_verification_res =
        vrf.verify(&secret_key.verifying_key().to_sec1_bytes(), &pi, &message);
    if let Ok(_) = vrf_verification_res {
        println!("VRF Verification Done");
    } else if let Err(err) = vrf_verification_res {
        println!("VRF Verification Failed, Error: {:?}", err)
    }
}
