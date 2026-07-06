//! holepunching module for inter-network connections

use quinn::Endpoint;

/// these are just client objects but managed
/// by a client.
/// 
/// client will maintain a map of Direct objects which
/// are UDP sockets that given a public,private pair
/// send packets until a connection is established,
/// where they are upgraded to quic connections
/// 
/// and since we remodelled the clients to talk to
/// each other this will be no different from communicating
/// with a relay just directly instead of thru a server
pub(crate) struct Direct {
    endpoint: Endpoint,

}