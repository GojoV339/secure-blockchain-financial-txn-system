require("@nomicfoundation/hardhat-ethers");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },

  networks: {
    // Ganache GUI / Ganache CLI — connect with: npx hardhat run scripts/deploy.js --network ganache
    ganache: {
      url: process.env.GANACHE_URL || "http://127.0.0.1:7545",
      chainId: 1337,
    },

    // Hardhat built-in node — start with: npx hardhat node
    // Then deploy with: npx hardhat run scripts/deploy.js --network localhost
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
  },

  paths: {
    sources: "./contracts",
    scripts: "./scripts",
    artifacts: "./artifacts",
    cache: "./cache",
  },
};
