from pathlib import Path
from legosec.sdk.sdk import SecureChannelSDK

__all__ = [
    "connect_to_kdc",
    "start_peer_listener",
    "connect_to_peer",
    "send_message_to_peer",
    "get_identity_status",
    "list_authorized_peers",
    "add_authorize_peer",
]


def connect_to_kdc(client_name="SecureClient", identity_dir="."):
    """
    Initialize the SecureChannelSDK and connect to the always-on KDC.
    
    Returns:
        SecureChannelSDK instance ready for use.
    """
    sdk = SecureChannelSDK(client_name=client_name, identity_dir=identity_dir)
    sdk.connect_to_kdc()
    return sdk


def start_peer_listener(sdk: SecureChannelSDK, port=6000):
    """
    Start a background listener thread to accept secure connections from peers.
    
    Args:
        sdk: Initialized SecureChannelSDK instance
        port: Port to listen on (default: 6000)
    """
    sdk.listen_for_peers(port=port)


def connect_to_peer(sdk: SecureChannelSDK, peer_id: str, port=6000):
    """
    Connect securely to a registered peer using ECDH or fallback to PSK.
    
    Args:
        sdk: Initialized SecureChannelSDK instance
        peer_id: Identifier of the target peer
        port: Port where the peer is listening (default: 6000)
        
    Returns:
        EncryptedSocket or PSK-secured Connection object
    """
    return sdk.connect_to_peer(peer_id=peer_id, port=port)


def send_message_to_peer(conn, message: str):
    """
    Send a UTF-8 string message to a peer over an established secure channel.
    
    Args:
        conn: EncryptedSocket or secure Connection object
        message: Message string to send
    
    Returns:
        The peer's response (decoded)
    """
    if isinstance(message, str):
        message = message.encode()

    conn.send(message)
    response = conn.recv(1024)
    print(f"[RESPONSE] {response.decode()}")
    conn.close()
    return response.decode()


def get_identity_status(sdk: SecureChannelSDK):
    """
    Check the current identity status (e.g., valid, expired, not registered).
    
    Args:
        sdk: Initialized SecureChannelSDK instance
        
    Returns:
        String status
    """
    return sdk.identity_manager.check_identity_expiration()


def list_authorized_peers(sdk: SecureChannelSDK):
    """
    List authorized peer client IDs for this SDK instance.
    
    Args:
        sdk: Initialized SecureChannelSDK instance
        
    Returns:
        List of peer client_ids
    """
    return sdk.identity_manager.get_authorized_peers()


def add_authorize_peer(sdk: SecureChannelSDK, peer_id: str):
    """
    Authorize a peer client ID for this SDK instance.
    
    Args:
        sdk: Initialized SecureChannelSDK instance
        peer_id: Peer client ID to authorize
    """
    sdk.identity_manager.authorize_peer(peer_id)