"""
Blockchain configuration and Web3 utilities for the Anonymous Complaint System
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from web3 import Web3
from eth_account import Account
from hexbytes import HexBytes
import hashlib
from datetime import datetime

logger = logging.getLogger(__name__)

class BlockchainConfig:
    """Blockchain configuration and utilities"""
    
    def __init__(self):
        """Initialize blockchain configuration"""
        self.web3 = None
        self.contract = None
        self.account = None
        self._initialize_web3()
        self._load_contract()
    
    def _initialize_web3(self):
        """Initialize Web3 connection"""
        try:
            # Get RPC URL from environment
            rpc_url = os.getenv('ETHEREUM_RPC_URL', 'https://sepolia.infura.io/v3/YOUR_PROJECT_ID')
            
            if 'YOUR_PROJECT_ID' in rpc_url:
                logger.warning("Please set ETHEREUM_RPC_URL environment variable with your Infura/Alchemy endpoint")
                return
            
            # Initialize Web3
            self.web3 = Web3(Web3.HTTPProvider(rpc_url))
            
            # Check connection
            if self.web3.is_connected():
                logger.info(f"Connected to Ethereum network. Chain ID: {self.web3.eth.chain_id}")
                
                # Load account from private key
                private_key = os.getenv('ETHEREUM_PRIVATE_KEY')
                if private_key:
                    self.account = Account.from_key(private_key)
                    logger.info(f"Loaded account: {self.account.address}")
                else:
                    logger.warning("ETHEREUM_PRIVATE_KEY not set. Contract interactions will be read-only.")
            else:
                logger.error("Failed to connect to Ethereum network")
                
        except Exception as e:
            logger.error(f"Error initializing Web3: {str(e)}")
    
    def _load_contract(self):
        """Load smart contract"""
        try:
            contract_address = os.getenv('COMPLAINT_CONTRACT_ADDRESS')
            contract_abi_path = os.getenv('COMPLAINT_CONTRACT_ABI_PATH', 'config/complaint_contract_abi.json')
            
            if not contract_address:
                logger.warning("COMPLAINT_CONTRACT_ADDRESS not set. Contract interactions disabled.")
                return
            
            if not os.path.exists(contract_abi_path):
                logger.warning(f"Contract ABI file not found: {contract_abi_path}")
                return
            
            # Load contract ABI
            with open(contract_abi_path, 'r') as f:
                contract_abi = json.load(f)
            
            # Initialize contract
            if self.web3:
                self.contract = self.web3.eth.contract(
                    address=Web3.to_checksum_address(contract_address),
                    abi=contract_abi
                )
                logger.info(f"Loaded contract at: {contract_address}")
            
        except Exception as e:
            logger.error(f"Error loading contract: {str(e)}")
    
    def is_ready(self) -> bool:
        """Check if blockchain connection is ready"""
        return self.web3 is not None and self.web3.is_connected() and self.contract is not None
    
    def hash_student_id(self, student_id: str, salt: str = None) -> str:
        """Create anonymous hash of student ID"""
        if salt is None:
            salt = os.getenv('STUDENT_ID_SALT', 'default_salt_change_in_production')
        
        # Combine student ID with salt and hash
        combined = f"{student_id}:{salt}:{datetime.now().strftime('%Y-%m-%d')}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def hash_complaint_content(self, content: str) -> str:
        """Create hash of complaint content for blockchain storage"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def submit_complaint_to_blockchain(self, hashed_student_id: str, complaint_hash: str, faculty_id: str) -> Optional[str]:
        """Submit complaint to blockchain"""
        if not self.is_ready() or not self.account:
            logger.error("Blockchain not ready or no account configured")
            return None

        try:
            logger.info(f"Submitting complaint to blockchain for faculty: {faculty_id}")

            # Estimate gas first
            try:
                gas_estimate = self.contract.functions.submitComplaint(
                    hashed_student_id,
                    complaint_hash,
                    faculty_id
                ).estimate_gas({'from': self.account.address})

                # Add 20% buffer to gas estimate
                gas_limit = int(gas_estimate * 1.2)
                logger.info(f"Gas estimate: {gas_estimate}, using limit: {gas_limit}")

            except Exception as gas_error:
                logger.warning(f"Gas estimation failed: {gas_error}, using default")
                gas_limit = 300000  # Increased default gas limit

            # Get current gas price with fallback
            try:
                current_gas_price = self.web3.eth.gas_price
                # Use current gas price + 10% for faster confirmation
                gas_price = int(current_gas_price * 1.1)
                logger.info(f"Using gas price: {self.web3.from_wei(gas_price, 'gwei')} Gwei")
            except Exception as price_error:
                logger.warning(f"Gas price fetch failed: {price_error}, using default")
                gas_price = self.web3.to_wei('25', 'gwei')  # Increased default gas price

            # Get nonce
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            logger.info(f"Using nonce: {nonce}")

            # Build transaction
            transaction = self.contract.functions.submitComplaint(
                hashed_student_id,
                complaint_hash,
                faculty_id
            ).build_transaction({
                'from': self.account.address,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'nonce': nonce
            })

            logger.info(f"Transaction built: gas={gas_limit}, gasPrice={self.web3.from_wei(gas_price, 'gwei')} Gwei")

            # Sign transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.account.key)

            # Send transaction
            logger.info("Sending transaction to blockchain...")
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            logger.info(f"Transaction sent: {tx_hash_hex}")

            # Wait for confirmation with shorter timeout
            logger.info("Waiting for transaction confirmation...")
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)

            if receipt.status == 1:
                logger.info(f"✅ Complaint submitted to blockchain successfully! TX: {tx_hash_hex}")
                logger.info(f"Gas used: {receipt.gasUsed}/{gas_limit}")
                return tx_hash_hex
            else:
                logger.error(f"❌ Transaction failed with status 0. TX: {tx_hash_hex}")
                logger.error(f"Gas used: {receipt.gasUsed}/{gas_limit}")
                return None

        except Exception as e:
            logger.error(f"❌ Error submitting complaint to blockchain: {str(e)}")
            # Log more details for debugging
            import traceback
            logger.error(f"Full error trace: {traceback.format_exc()}")
            return None
    
    def check_daily_limit(self, hashed_student_id: str) -> bool:
        """Check if student can submit complaint today"""
        if not self.is_ready():
            logger.error("Blockchain not ready")
            return False
        
        try:
            can_submit = self.contract.functions.checkDailyLimit(hashed_student_id).call()
            return can_submit
        except Exception as e:
            logger.error(f"Error checking daily limit: {str(e)}")
            return False
    
    def get_complaints_by_faculty(self, faculty_id: str) -> list:
        """Get complaints for a specific faculty member"""
        if not self.is_ready():
            logger.error("Blockchain not ready")
            return []
        
        try:
            complaints = self.contract.functions.getComplaintsByFaculty(faculty_id).call()
            return complaints
        except Exception as e:
            logger.error(f"Error getting complaints by faculty: {str(e)}")
            return []
    
    def get_transaction_details(self, tx_hash: str) -> Optional[Dict[str, Any]]:
        """Get transaction details"""
        if not self.web3:
            return None
        
        try:
            tx = self.web3.eth.get_transaction(tx_hash)
            receipt = self.web3.eth.get_transaction_receipt(tx_hash)
            
            return {
                'hash': tx_hash,
                'block_number': receipt.blockNumber,
                'gas_used': receipt.gasUsed,
                'status': receipt.status,
                'timestamp': self.web3.eth.get_block(receipt.blockNumber).timestamp
            }
        except Exception as e:
            logger.error(f"Error getting transaction details: {str(e)}")
            return None

# Global instance
_blockchain_config = None

def get_blockchain_config():
    """Get the global blockchain configuration instance"""
    global _blockchain_config
    if _blockchain_config is None:
        _blockchain_config = BlockchainConfig()
    return _blockchain_config
