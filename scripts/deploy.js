/**
 * Hardhat deploy script for TransactionContract.
 *
 * Usage:
 *   # Against Ganache (port 7545)
 *   npx hardhat run scripts/deploy.js --network ganache
 *
 *   # Against Hardhat built-in node (port 8545)
 *   npx hardhat node          # terminal 1
 *   npx hardhat run scripts/deploy.js --network localhost   # terminal 2
 *
 * After deployment, `deployment.json` is written to the project root.
 * The Python layer (blockchain/contract.py) reads this file to find the
 * contract address automatically.
 */

const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("═══════════════════════════════════════════════════════");
  console.log("  Deploying TransactionContract");
  console.log("═══════════════════════════════════════════════════════");
  console.log(`  Network  : ${network.name}`);
  console.log(`  Deployer : ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`  Balance  : ${ethers.formatEther(balance)} ETH`);
  console.log("───────────────────────────────────────────────────────");

  // Deploy
  const ContractFactory = await ethers.getContractFactory("TransactionContract");
  const contract = await ContractFactory.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  const deployTx = contract.deploymentTransaction();
  const receipt = await deployTx.wait();

  console.log(`  Contract : ${contractAddress}`);
  console.log(`  Block    : ${receipt.blockNumber}`);
  console.log(`  Gas used : ${receipt.gasUsed.toString()}`);
  console.log("═══════════════════════════════════════════════════════");
  console.log("  TransactionContract deployed successfully ✓");
  console.log("═══════════════════════════════════════════════════════");

  // Save deployment info for Python layer
  const deploymentInfo = {
    contractName: "TransactionContract",
    address: contractAddress,
    deployer: deployer.address,
    network: network.name,
    blockNumber: receipt.blockNumber,
    transactionHash: deployTx.hash,
    deployedAt: new Date().toISOString(),
  };

  const deploymentPath = path.join(__dirname, "..", "deployment.json");
  fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\n  Deployment info saved → deployment.json`);
  console.log(`  Load in Python: ContractInterface.from_deployment_file(w3)\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
