# alice.py
from sdk import SecureChannelSDK
import logging
import time

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('alice.log')
    ]
)

def alice_program():
    logging.info("=== ALICE STARTING ===")
    
    try:
        alice = SecureChannelSDK(
            client_name="Alice",
            client_id="alice_client_001",
            kdc_port=5000,
            peer_port=6002
        )
        
        if not alice.identity_manager.is_registered():
            logging.info("Registering with KDC...")
            if not alice.connect_to_kdc():
                logging.error("Registration failed")
                return
        
        logging.info("Starting listener...")
        alice.listen_for_peers()
        
        # Keep alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logging.info("\nShutdown requested")
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        logging.info("=== ALICE EXITING ===")

if __name__ == "__main__":
    alice_program()