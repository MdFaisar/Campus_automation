"""
Smart contract deployment script for the Anonymous Complaint System
"""

import os
import json
import logging
from web3 import Web3
from eth_account import Account
from solcx import compile_source, install_solc
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def compile_contract():
    """Compile the Solidity contract"""
    try:
        # Install Solidity compiler if not present
        try:
            install_solc('0.8.19')
        except Exception as e:
            logger.warning(f"Could not install solc: {e}")
        
        # Read contract source
        contract_path = Path(__file__).parent.parent / 'contracts' / 'ComplaintContract.sol'
        
        if not contract_path.exists():
            raise FileNotFoundError(f"Contract file not found: {contract_path}")
        
        with open(contract_path, 'r') as f:
            contract_source = f.read()
        
        # Compile contract
        logger.info("Compiling contract...")
        compiled_sol = compile_source(contract_source, solc_version='0.8.19')
        
        # Get contract interface
        contract_id, contract_interface = compiled_sol.popitem()
        
        logger.info("Contract compiled successfully")
        return contract_interface
        
    except Exception as e:
        logger.error(f"Error compiling contract: {str(e)}")
        raise

def deploy_contract():
    """Deploy the contract to the blockchain"""
    try:
        # Get environment variables
        rpc_url = os.getenv('ETHEREUM_RPC_URL')
        private_key = os.getenv('ETHEREUM_PRIVATE_KEY')
        
        if not rpc_url:
            raise ValueError("ETHEREUM_RPC_URL environment variable not set")
        
        if not private_key:
            raise ValueError("ETHEREUM_PRIVATE_KEY environment variable not set")
        
        # Initialize Web3
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        if not w3.is_connected():
            raise ConnectionError("Failed to connect to Ethereum network")
        
        logger.info(f"Connected to network. Chain ID: {w3.eth.chain_id}")
        
        # Load account
        account = Account.from_key(private_key)
        logger.info(f"Deploying from account: {account.address}")
        
        # Check balance
        balance = w3.eth.get_balance(account.address)
        balance_eth = w3.from_wei(balance, 'ether')
        logger.info(f"Account balance: {balance_eth} ETH")
        
        if balance_eth < 0.01:  # Minimum balance check
            logger.warning("Low account balance. Deployment may fail.")
        
        # Compile contract
        contract_interface = compile_contract()
        
        # Create contract instance
        contract = w3.eth.contract(
            abi=contract_interface['abi'],
            bytecode=contract_interface['bin']
        )
        
        # Estimate gas
        gas_estimate = contract.constructor().estimate_gas()
        logger.info(f"Estimated gas: {gas_estimate}")
        
        # Get current gas price
        gas_price = w3.eth.gas_price
        logger.info(f"Current gas price: {w3.from_wei(gas_price, 'gwei')} Gwei")
        
        # Build deployment transaction
        transaction = contract.constructor().build_transaction({
            'from': account.address,
            'gas': gas_estimate + 50000,  # Add buffer
            'gasPrice': gas_price,
            'nonce': w3.eth.get_transaction_count(account.address)
        })
        
        # Sign transaction
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
        
        # Send transaction
        logger.info("Sending deployment transaction...")
        tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        logger.info(f"Transaction hash: {tx_hash.hex()}")
        
        # Wait for confirmation
        logger.info("Waiting for transaction confirmation...")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        
        if receipt.status == 1:
            contract_address = receipt.contractAddress
            logger.info(f"Contract deployed successfully!")
            logger.info(f"Contract address: {contract_address}")
            logger.info(f"Gas used: {receipt.gasUsed}")
            
            # Save deployment info
            save_deployment_info(contract_address, contract_interface['abi'], tx_hash.hex(), receipt)
            
            return contract_address, contract_interface['abi']
        else:
            logger.error("Contract deployment failed")
            return None, None
            
    except Exception as e:
        logger.error(f"Error deploying contract: {str(e)}")
        raise

def save_deployment_info(contract_address, abi, tx_hash, receipt):
    """Save deployment information to files"""
    try:
        # Create config directory if it doesn't exist
        config_dir = Path(__file__).parent.parent / 'config'
        config_dir.mkdir(exist_ok=True)
        
        # Save ABI
        abi_path = config_dir / 'complaint_contract_abi.json'
        with open(abi_path, 'w') as f:
            json.dump(abi, f, indent=2)
        logger.info(f"ABI saved to: {abi_path}")
        
        # Save deployment info
        deployment_info = {
            'contract_address': contract_address,
            'transaction_hash': tx_hash,
            'block_number': receipt.blockNumber,
            'gas_used': receipt.gasUsed,
            'deployment_timestamp': receipt.blockNumber,  # Approximate
            'network_info': {
                'chain_id': receipt.blockNumber,  # Will be updated with actual chain ID
                'rpc_url': os.getenv('ETHEREUM_RPC_URL', 'Not specified')
            }
        }
        
        deployment_path = config_dir / 'complaint_contract_deployment.json'
        with open(deployment_path, 'w') as f:
            json.dump(deployment_info, f, indent=2)
        logger.info(f"Deployment info saved to: {deployment_path}")
        
        # Create .env template
        env_template = f"""
# Add these to your .env file:
COMPLAINT_CONTRACT_ADDRESS={contract_address}
COMPLAINT_CONTRACT_ABI_PATH=config/complaint_contract_abi.json

# Make sure you also have:
# ETHEREUM_RPC_URL=your_rpc_url_here
# ETHEREUM_PRIVATE_KEY=your_private_key_here
# STUDENT_ID_SALT=your_random_salt_here
"""
        
        env_template_path = config_dir / 'env_template.txt'
        with open(env_template_path, 'w') as f:
            f.write(env_template)
        logger.info(f"Environment template saved to: {env_template_path}")
        
    except Exception as e:
        logger.error(f"Error saving deployment info: {str(e)}")

def verify_deployment(contract_address, abi):
    """Verify the deployed contract"""
    try:
        rpc_url = os.getenv('ETHEREUM_RPC_URL')
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Create contract instance
        contract = w3.eth.contract(address=contract_address, abi=abi)
        
        # Test basic functions
        logger.info("Verifying contract deployment...")
        
        # Check owner
        owner = contract.functions.owner().call()
        logger.info(f"Contract owner: {owner}")
        
        # Check total complaints (should be 0)
        total_complaints = contract.functions.getTotalComplaints().call()
        logger.info(f"Total complaints: {total_complaints}")
        
        # Check contract stats
        total, active = contract.functions.getContractStats().call()
        logger.info(f"Contract stats - Total: {total}, Active: {active}")
        
        logger.info("Contract verification successful!")
        return True
        
    except Exception as e:
        logger.error(f"Error verifying contract: {str(e)}")
        return False

def main():
    """Main deployment function"""
    try:
        logger.info("Starting contract deployment...")
        
        # Deploy contract
        contract_address, abi = deploy_contract()
        
        if contract_address and abi:
            # Verify deployment
            if verify_deployment(contract_address, abi):
                logger.info("Deployment completed successfully!")
                logger.info(f"Contract Address: {contract_address}")
                logger.info("Don't forget to update your .env file with the contract address!")
            else:
                logger.error("Deployment verification failed")
        else:
            logger.error("Deployment failed")
            
    except Exception as e:
        logger.error(f"Deployment error: {str(e)}")

if __name__ == "__main__":
    main()
