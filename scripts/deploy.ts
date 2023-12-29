import { ethers } from "hardhat";

async function main() {

  const entryPoint = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
  const walliShield = "0x9A5083790f6883D4B328323120Ad91D3d8394D30";
  const connextGoerli = "0xFCa08024A6D4bCc87275b1E4A1E22B71fAD7f649";
  const connextMumbai = "0x2334937846Ab2A3FCE747b32587e1A1A2f6EEC5a";

  const walliFactory = await ethers.deployContract("WalliFactory", [entryPoint, walliShield, connextMumbai]);
  await walliFactory.waitForDeployment();

  // if (process.env.host == "development") {
  // }

  console.log(
    'Deployed Walli Factory: ', await walliFactory.getAddress(),
  );

}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
