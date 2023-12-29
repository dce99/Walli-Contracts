import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import 'dotenv/config'

const ALCHEMY_API_KEY_GOERLI = process.env.ALCHEMY_API_KEY_GOERLI?.toString();
const PRIVATE_KEY = process.env.PRIVATE_KEY?.toString() as string;
const ALCHEMY_API_KEY_MUMBAI = process.env.ALCHEMY_API_KEY_MUMBAI?.toString();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 100,
      },
      viaIR: true,
    },
  },
  networks: {
    goerli: {
      url: `https://eth-goerli.g.alchemy.com/v2/${ALCHEMY_API_KEY_GOERLI}`,
      accounts: [PRIVATE_KEY]
    },
    mumbai: {
      url: `https://polygon-mumbai.g.alchemy.com/v2/${ALCHEMY_API_KEY_MUMBAI}`,
      accounts: [PRIVATE_KEY]
    }
  }
};

export default config;
