import {
    loadFixture, time,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { ethers } from "hardhat";
import { ERC1967Proxy__factory, Walli, Walli__factory } from "../typechain-types";
import { abi as WalliAbi } from "../artifacts/contracts/core/Walli.sol/Walli.json"
import { expect } from "chai"
import { UserOperationStruct } from "../typechain-types/contracts/core/BaseAccount";


describe("Walli", function () {

    // this.beforeAll(deployWalli);

    async function deployWalli() {
        const [owner, addr1, addr2, addr3, addr4, addr5, addr6, addr7, addr8] = await ethers.getSigners();
        const walliFactory = await ethers.deployContract("WalliFactory", [addr5, addr6, addr8]);
        await walliFactory.waitForDeployment();
        const tx = await walliFactory.createAccount(owner, 0);
        await tx.wait();

        const proxyAddress = await walliFactory.getComputeAddress(owner, 0);
        console.log("Proxy Address: ", proxyAddress);
        const proxy = ERC1967Proxy__factory.connect(proxyAddress, ethers.provider);
        // const proxy = await ethers.getContractAt("ERC1967Proxy", proxyAddress);
        return { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, addr5, addr6, addr7, addr8, walliShield: addr6, entryPoint: addr5 };
    }

    async function deployToken() {
        const [owner] = await ethers.getSigners();
        const token = await ethers.deployContract("TetherToken", [ethers.parseEther("100")]);
        await token.waitForDeployment();
        return { token, owner };
    }

    it("Should deploy wallet and set owner", async function () {
        const { proxyAddress, owner } = await loadFixture(deployWalli);

        const iface = new ethers.Interface(WalliAbi);
        const tx = {
            to: proxyAddress,
            // data: iface.encodeFunctionData("owner", [])
            data: Walli__factory.createInterface().encodeFunctionData("owner")
        };
        const ret = await ethers.provider.call(tx);
        // const res = iface.decodeFunctionResult("owner", ret);
        const res = Walli__factory.createInterface().decodeFunctionResult("owner", ret);
        const _owner = ethers.getAddress(res[0]);

        expect(_owner).to.be.equal(await owner.getAddress());
    });


    async function initiateGuardianAdditions() {
        const { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, walliShield, entryPoint } = await loadFixture(deployWalli);

        const guardianArg1 = await addr1.getAddress();
        const guardianArg2 = await addr2.getAddress();
        const guardianArg3 = await addr3.getAddress();
        const tx1 = {
            to: proxyAddress,
            data: Walli__factory.createInterface().encodeFunctionData("initiateGuardianAddition", [guardianArg1, ethers.encodeBytes32String("Bunty")])
        };
        const txResponse1 = await owner.sendTransaction(tx1);
        await txResponse1.wait();

        const tx2 = {
            to: proxyAddress,
            data: Walli__factory.createInterface().encodeFunctionData("initiateGuardianAddition", [guardianArg2, ethers.encodeBytes32String("Guddu")])
        };
        const txResponse2 = await owner.sendTransaction(tx2);
        await txResponse2.wait();

        const tx3 = {
            to: proxyAddress,
            data: Walli__factory.createInterface().encodeFunctionData("initiateGuardianAddition", [guardianArg3, ethers.encodeBytes32String("Kiddo")])
        };
        const txResponse3 = await owner.sendTransaction(tx3);
        await txResponse3.wait();

        return { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3, walliShield, entryPoint };
    }

    describe("Guardians", function () {

        describe("Guardian Addition", function () {


            it("Should initiate guardian addition and pendingGuardianAdditions should contain given guardian address", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianAdditions);
                const tx = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getPendingGuardianAdditions")
                };
                const ret = await ethers.provider.call(tx);
                const res = Walli__factory.createInterface().decodeFunctionResult("getPendingGuardianAdditions", ret);
                const pendings = res[0] as Walli.RequestConfigStructOutput[];

                // console.log(pendings[0].profile.addr, guardianArg1, ethers.decodeBytes32String(pendings[0].profile.name) );
                expect(pendings[0].profile.addr).to.be.equal(guardianArg1);
                expect(ethers.decodeBytes32String(pendings[0].profile.name)).to.be.equal("Bunty");

            });

            it("Should cancel guardian addition", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianAdditions);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("cancelGuardianAddition", [guardianArg1])
                };
                const response = await owner.sendTransaction(tx1);
                await response.wait();
                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getPendingGuardianAdditions")
                };
                const ret = await ethers.provider.call(tx2);
                const res = Walli__factory.createInterface().decodeFunctionResult("getPendingGuardianAdditions", ret);
                const pendings = res[0] as Walli.RequestConfigStructOutput[];

                expect(res[1]).to.be.equal(2);
                expect(pendings[0].profile.addr).to.not.be.equal(guardianArg1);
            });

            it("Should revert with 'Walli: No guardian addition initiated' ", async function () {
                const { proxyAddress, proxy, owner, addr1 } = await loadFixture(deployWalli);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [await addr1.getAddress()])
                };

                const response = owner.sendTransaction(tx1);
                await expect(response).to.be.revertedWith("Walli: No guardian addition initiated");
            });

            it("Should revert with 'Walli: Ongoing security period' ", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianAdditions);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg1])
                };

                const response = owner.sendTransaction(tx1);
                await expect(response).to.be.revertedWith("Walli: Ongoing security period");
            });

            it("Should finalise guardian addition and authorisedGuardians should have given guardian", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianAdditions);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg1])
                };

                await time.increaseTo(await time.latest() + 24 * 60 * 60);
                const response = await owner.sendTransaction(tx1);
                await response.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getGuardians")
                };
                let ret = await ethers.provider.call(tx2);
                let res = Walli__factory.createInterface().decodeFunctionResult("getGuardians", ret);
                const guardians = res[0] as Walli.ProfileStructOutput[];
                expect(res[1]).to.be.equal(1);
                expect(guardians[0].addr).to.be.equal(guardianArg1);


                const tx3 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("isGuardian", [guardianArg1])
                };
                ret = await ethers.provider.call(tx3);
                res = Walli__factory.createInterface().decodeFunctionResult("isGuardian", ret);
                const isGuardian = res[0] as boolean;
                expect(isGuardian).to.be.true;
            });
        });

        describe("Guardian Removal", function () {

            async function initiateGuardianRemovals() {
                const { proxyAddress, proxy, owner, addr1, addr2, addr3, guardianArg1 } = await loadFixture(initiateGuardianAdditions);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg1])
                };

                await time.increaseTo(await time.latest() + 24 * 60 * 60);
                let response = await owner.sendTransaction(tx1);
                await response.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("initiateGuardianRemoval", [guardianArg1, ethers.encodeBytes32String("Bunty")])
                };
                response = await owner.sendTransaction(tx2);
                await response.wait();

                return { proxyAddress, proxy, owner, addr1, addr2, addr3, guardianArg1 };
            }

            this.beforeEach(initiateGuardianRemovals);

            it("Should initiate guardian removal and pendingGuardianRemovals should contain given guardian address", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianRemovals);
                const tx = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getPendingGuardianRemovals")
                };
                const ret = await ethers.provider.call(tx);
                const res = Walli__factory.createInterface().decodeFunctionResult("getPendingGuardianRemovals", ret);
                const pendings = res[0] as Walli.RequestConfigStructOutput[];

                expect(pendings[0].profile.addr).to.be.equal(guardianArg1);
                expect(ethers.decodeBytes32String(pendings[0].profile.name)).to.be.equal("Bunty");

            });

            it("Should cancel guardian removal", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianRemovals);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("cancelGuardianRemoval", [guardianArg1])
                };
                const response = await owner.sendTransaction(tx1);
                await response.wait();
                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getPendingGuardianRemovals")
                };
                const ret = await ethers.provider.call(tx2);
                const res = Walli__factory.createInterface().decodeFunctionResult("getPendingGuardianRemovals", ret);
                const pendings = res[0] as Walli.RequestConfigStructOutput[];

                expect(res[1]).to.be.equal(0);
                expect(pendings[0].profile.addr).to.not.be.equal(guardianArg1);
            });

            it("Should revert with 'Walli: No guardian removal initiated' ", async function () {
                const { proxyAddress, proxy, owner, addr1 } = await loadFixture(deployWalli);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianRemoval", [await addr1.getAddress()])
                };

                const response = owner.sendTransaction(tx1);
                await expect(response).to.be.revertedWith("Walli: No guardian removal initiated");
            });

            it("Should revert with 'Walli: Ongoing security period' ", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianRemovals);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianRemoval", [guardianArg1])
                };

                const response = owner.sendTransaction(tx1);
                await expect(response).to.be.revertedWith("Walli: Ongoing security period");
            });

            it("Should finalise guardian removal and authorisedGuardians should not have given guardian", async function () {
                const { proxyAddress, proxy, owner, addr1, guardianArg1 } = await loadFixture(initiateGuardianRemovals);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianRemoval", [guardianArg1])
                };

                await time.increaseTo(await time.latest() + 24 * 60 * 60);
                const response = await owner.sendTransaction(tx1);
                await response.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getGuardians")
                };
                let ret = await ethers.provider.call(tx2);
                let res = Walli__factory.createInterface().decodeFunctionResult("getGuardians", ret);
                const guardians = res[0] as Walli.ProfileStructOutput[];
                expect(res[1]).to.be.equal(0);

                const tx3 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("isGuardian", [guardianArg1])
                };
                ret = await ethers.provider.call(tx3);
                res = Walli__factory.createInterface().decodeFunctionResult("isGuardian", ret);
                const isGuardian = res[0] as boolean;
                expect(isGuardian).to.be.false;
            });
        });

    });



    describe("Social Recovery", function () {

        async function finalise3Guardians() {
            const { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateGuardianAdditions);

            await time.increaseTo(await time.latest() + 24 * 60 * 60);
            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg1])
            };
            let response = await owner.sendTransaction(tx1);
            await response.wait();

            const tx2 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg2])
            };
            response = await owner.sendTransaction(tx2);
            await response.wait();

            const tx3 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg3])
            };
            response = await owner.sendTransaction(tx3);
            await response.wait();

            const tx4 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getGuardians")
            }
            const data = await ethers.provider.call(tx4);
            const res = Walli__factory.createInterface().decodeFunctionResult("getGuardians", data);
            expect(res[1]).to.be.equal(3);

            return { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 };
        }

        async function initiateRecovery() {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(finalise3Guardians);

            const newOwner = await addr4.getAddress();
            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("initiateRecovery", [newOwner])
            }
            let res1 = await addr1.sendTransaction(tx1);
            await res1.wait();

            const tx2 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getRecovery")
            }
            const data = await owner.call(tx2);
            const res2 = Walli__factory.createInterface().decodeFunctionResult("getRecovery", data);
            const recoveryOwner = res2[0];
            expect(recoveryOwner).to.be.equal(newOwner);

            return { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 };
        }

        it("Should revert with 'Walli: Must be Guardian", async function () {
            const { owner, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(finalise3Guardians);

            const newOwner = await addr4.getAddress()
            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("initiateRecovery", [newOwner])
            }
            const res = owner.sendTransaction(tx1);
            await expect(res).to.be.revertedWith("Walli: Must be Guardian");
        });

        it("Should initiate recovery", async function () {
            await loadFixture(initiateRecovery);
        });

        it("Should confirm recovery", async function () {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateRecovery);

            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("confirmRecovery")
            }
            const res1 = await addr1.sendTransaction(tx1);
            await res1.wait();

            const res2 = addr1.sendTransaction(tx1);
            await expect(res2).to.be.revertedWith("Walli: Recovery already confirmed");
        });

        it("Should revert with 'Walli: Ongoing recovery period'", async function () {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateRecovery);

            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseRecovery")
            }
            const res = addr1.sendTransaction(tx1);
            await expect(res).to.be.revertedWith("Walli: Ongoing recovery period");
        })

        it("Should revert with 'Walli: Recovery confirmation still pending from guardians'", async function () {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateRecovery);

            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("confirmRecovery")
            }
            const res1 = await addr1.sendTransaction(tx1);
            await res1.wait();

            await time.increaseTo(await time.latest() + 5 * 24 * 60 * 60);
            const tx2 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseRecovery")
            }
            const res = addr1.sendTransaction(tx2);
            await expect(res).to.be.revertedWith("Walli: Recovery confirmation still pending from guardians");
        })

        it("Should finalise recovery and set new owner as the owner of walli", async function () {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateRecovery);

            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("confirmRecovery")
            }
            const res1 = await addr1.sendTransaction(tx1);
            await res1.wait();

            const tx2 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("confirmRecovery")
            }
            const res2 = await addr2.sendTransaction(tx2);
            await res2.wait();

            await time.increaseTo(await time.latest() + 5 * 24 * 60 * 60);
            const tx3 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("finaliseRecovery")
            }
            const res3 = await addr1.sendTransaction(tx3);
            await res3.wait();

            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("owner")
            })
            const newOwner = Walli__factory.createInterface().decodeFunctionResult("owner", data)[0];
            expect(newOwner).to.be.equal(await addr4.getAddress());

        });

        it("Should cancel recovery and getRecovery should revert with 'Walli: No recovery pending request' ", async function () {
            const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiateRecovery);

            const tx1 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("cancelRecovery")
            }
            const res1 = await addr1.sendTransaction(tx1);
            await res1.wait();

            const tx2 = {
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("cancelRecovery")
            }
            const res2 = await addr2.sendTransaction(tx2);
            await res2.wait();


            const data = ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getRecovery")
            });
            await expect(data).to.be.revertedWith("Walli: No recovery pending request")

        });

    })


    describe("Lock", function () {

        it("Should set lock", async function () {
            const { proxyAddress, owner } = await loadFixture(deployWalli);

            const latest = await time.latest();
            const res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("lock")
            })
            await res.wait();

            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getLock")
            });
            const lockRelease = Walli__factory.createInterface().decodeFunctionResult("getLock", data)[0];
            expect(lockRelease).to.be.greaterThanOrEqual(latest + 7 * 24 * 60 * 60);
        });

        it("Should unlock", async function () {
            const { proxyAddress, owner } = await loadFixture(deployWalli);

            const latest = await time.latest();
            let res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("lock")
            })
            await res.wait();

            res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("unlock")
            })
            await res.wait();

            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getLock")
            });
            const lockRelease = Walli__factory.createInterface().decodeFunctionResult("getLock", data)[0];
            expect(lockRelease).to.be.greaterThanOrEqual(0);
        });

    });


    describe("Trusted Contacts", function () {

        it("Should add a trusted contact", async function () {
            const { proxyAddress, owner, addr2 } = await loadFixture(deployWalli);

            const trustedContact = await addr2.getAddress();
            const res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("addTrustedContact", [trustedContact, ethers.encodeBytes32String("Bunty")])
            })
            await res.wait();

            let data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("isTrustedContact", [trustedContact])
            });
            const isTrustedContact = Walli__factory.createInterface().decodeFunctionResult("isTrustedContact", data)[0] as boolean;
            expect(isTrustedContact).to.be.true;

            data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getTrustedContacts", [0])
            });
            const res2 = Walli__factory.createInterface().decodeFunctionResult("getTrustedContacts", data);
            expect(res2[1]).to.be.equal(1);
        });

        it("Should remove a trusted contact", async function () {
            const { proxyAddress, owner, addr2 } = await loadFixture(deployWalli);

            const trustedContact = await addr2.getAddress();
            let res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("addTrustedContact", [trustedContact, ethers.encodeBytes32String("Bunty")])
            })
            await res.wait();

            let data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("isTrustedContact", [trustedContact])
            });
            let isTrustedContact = Walli__factory.createInterface().decodeFunctionResult("isTrustedContact", data)[0] as boolean;
            expect(isTrustedContact).to.be.true;

            res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("removeTrustedContact", [trustedContact])
            })
            await res.wait();

            data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("isTrustedContact", [trustedContact])
            });
            isTrustedContact = Walli__factory.createInterface().decodeFunctionResult("isTrustedContact", data)[0] as boolean;
            expect(isTrustedContact).to.be.false;
        })
    });


    describe("Transfer Limits", function () {

        it("Should set native transfer limit", async function () {
            const { proxyAddress, owner } = await loadFixture(deployWalli);
            const res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("setNativeLimit", [ethers.parseEther("5")])
            })
            await res.wait();

            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getNativeLimit")
            });
            const limit = Walli__factory.createInterface().decodeFunctionResult("getNativeLimit", data)[0];
            expect(limit).to.be.greaterThanOrEqual(ethers.parseEther("5"));
        });

        it("Should set token transfer limit", async function () {
            const { proxyAddress, owner, addr2 } = await loadFixture(deployWalli);
            const tokenAddress = await addr2.getAddress();
            const res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("setTokenLimit", [tokenAddress, ethers.parseEther("5")])
            })
            await res.wait();

            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("getTokenLimit", [tokenAddress])
            });
            const limit = Walli__factory.createInterface().decodeFunctionResult("getTokenLimit", data)[0];
            expect(limit).to.be.greaterThanOrEqual(ethers.parseEther("5"));
        });
    });


    describe("Sessions", function () {

        async function generateSignatureAndMessageHash(selector: string, owner: any, walliShield: any, entryPoint: any, completeSignature: boolean = true) {
            const chaindId = 1;
            const hashedEmail = ethers.keccak256(ethers.solidityPacked(["string"], ["abc@example.com"]));
            const key = ethers.keccak256(ethers.solidityPacked(["string"], ["34r34rj34kk34rjk3rk3krjk34kr"]));
            const expiry = await time.latest() + 30 * 24 * 60 * 60;

            const messageHash = ethers.keccak256(ethers.solidityPacked(["string", "address", "uint256", "uint256"], [selector, entryPoint, chaindId, 0]));
            const message = ethers.getBytes(messageHash);
            let signatures = await owner.signMessage(message);
            if (completeSignature)
                signatures = (await walliShield.signMessage(message)) + signatures.slice(2);

            return { hashedEmail, signatures, messageHash, chaindId, key, expiry };
        }

        async function enable2FA() {
            const { proxyAddress, owner, walliShield, entryPoint, addr1, addr2, addr3, addr4 } = await loadFixture(deployWalli);

            const { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("enable2FA", owner, walliShield, entryPoint.address);
            const res = await owner.sendTransaction({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
            })
            await res.wait();
            
            const data = await ethers.provider.call({
                to: proxyAddress,
                data: Walli__factory.createInterface().encodeFunctionData("is2FAEnabled")
            })
            const is2FAEnabled = Walli__factory.createInterface().decodeFunctionResult("is2FAEnabled", data)[0] as boolean;
            expect(is2FAEnabled).to.be.true;

            return { proxyAddress, owner, walliShield, entryPoint, addr1, addr2, addr3, addr4 };
        }

        describe("2FA enable", function () {

            it("Should not enable 2FA and revert with  'Walli: Invalid message hash' ", async function () {
                const { proxyAddress, owner, addr5, walliShield, entryPoint } = await loadFixture(deployWalli);

                const { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("hehe", owner, walliShield, entryPoint.address);
                const res = owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
                })
                await expect(res).to.be.revertedWith("Walli: Invalid message hash");
            });

            it("Should not enable 2FA and revert with  'Walli: Invalid signature length' ", async function () {
                const { proxyAddress, owner, walliShield, entryPoint } = await loadFixture(deployWalli);

                const { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("enable2FA", owner, walliShield, entryPoint.address, false);
                const res = owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
                })
                await expect(res).to.be.revertedWith("Walli: Invalid signature length");
            });

            it("Should not enable 2FA and revert with  'Walli: Signature verification failed' ", async function () {
                const { proxyAddress, owner, walliShield, entryPoint, addr7 } = await loadFixture(deployWalli);

                const { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("enable2FA", owner, addr7, entryPoint.address);
                const res = owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
                })
                await expect(res).to.be.revertedWith("Walli: Signature verification failed");
            });

            it("Should enable 2FA", async function () {
                await loadFixture(enable2FA);
            });

            it("Should add session", async function () {

                const { proxyAddress, owner, walliShield, entryPoint } = await loadFixture(deployWalli);

                let { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("enable2FA", owner, walliShield, entryPoint.address);
                const res1 = owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
                })
                await expect(res1).not.to.be.reverted;

                await time.increaseTo(await time.latest() + 32 * 24 * 60 * 60 * 1000);
                ({ hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("addSession", owner, walliShield, entryPoint.address));
                const res2 = await owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("addSession", [hashedEmail, key, expiry, chaindId, messageHash, signatures])
                })
                await res2.wait();

                // const res3 = await owner.sendTransaction({
                //     to: proxyAddress,
                //     data: Walli__factory.createInterface().encodeFunctionData("clearAllSessions")
                // })
                // await res3.wait();

                const data = await ethers.provider.call({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("isValidSession", [key])
                })
                const isValidSession = Walli__factory.createInterface().decodeFunctionResult("isValidSession", data)[0] as boolean;
                expect(isValidSession).to.be.true;
            });
        })



        describe("2FA Removal", function () {

            async function finalise3GuardiansAndEnable2FA() {
                const { proxyAddress, proxy, owner, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3, walliShield, entryPoint } = await loadFixture(initiateGuardianAdditions);

                await time.increaseTo(await time.latest() + 24 * 60 * 60);
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg1])
                };
                let response = await owner.sendTransaction(tx1);
                await response.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg2])
                };
                response = await owner.sendTransaction(tx2);
                await response.wait();

                const tx3 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finaliseGuardianAddition", [guardianArg3])
                };
                response = await owner.sendTransaction(tx3);
                await response.wait();

                const tx4 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("getGuardians")
                }
                const data = await ethers.provider.call(tx4);
                const res = Walli__factory.createInterface().decodeFunctionResult("getGuardians", data);
                expect(res[1]).to.be.equal(3);

                const { hashedEmail, signatures, messageHash, chaindId, key, expiry } = await generateSignatureAndMessageHash("enable2FA", owner, walliShield, entryPoint.address);
                const res2 = owner.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("enable2FA", [hashedEmail, chaindId, messageHash, signatures, key, expiry])
                })
                await expect(res2).not.to.be.reverted;
                
                return { proxyAddress, proxy, owner, walliShield, entryPoint, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 };
            }

            async function initiate2FARemoval() {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(finalise3GuardiansAndEnable2FA);

                const latest = await time.latest();
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("initiate2FARemoval")
                }
                let res1 = await addr1.sendTransaction(tx1);
                await res1.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("get2FARemoval")
                }
                const data = await owner.call(tx2);
                const res2 = Walli__factory.createInterface().decodeFunctionResult("get2FARemoval", data);
                const finaliseAfter = res2[0];
                expect(finaliseAfter).to.be.greaterThanOrEqual(latest + 5 * 24 * 60 * 60);

                return { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 };
            }

            it("Should revert with 'Walli: Must be Guardian", async function () {
                const { owner, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(finalise3GuardiansAndEnable2FA);

                const newOwner = await addr4.getAddress()
                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("initiate2FARemoval")
                }
                const res = owner.sendTransaction(tx1);
                await expect(res).to.be.revertedWith("Walli: Must be Guardian");
            });

            it("Should initiate 2FA removal", async function () {
                await loadFixture(initiate2FARemoval);
            });

            it("Should confirm 2FA removal by a guardian", async function () {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiate2FARemoval);

                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("confirm2FARemoval")
                }
                const res1 = await addr1.sendTransaction(tx1);
                await res1.wait();

                const res2 = addr1.sendTransaction(tx1);
                await expect(res2).to.be.revertedWith("Walli: 2FA removal already confirmed");
            });

            it("Should revert with 'Walli: Ongoing security period'", async function () {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiate2FARemoval);

                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finalise2FARemoval")
                }
                const res = addr1.sendTransaction(tx1);
                await expect(res).to.be.revertedWith("Walli: Ongoing security period");
            })

            it("Should revert with 'Walli: 2FA removal confirmation still pending from guardians'", async function () {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiate2FARemoval);

                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("confirm2FARemoval")
                }
                const res1 = await addr1.sendTransaction(tx1);
                await res1.wait();

                await time.increaseTo(await time.latest() + 5 * 24 * 60 * 60);
                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finalise2FARemoval")
                }
                const res = addr1.sendTransaction(tx2);
                await expect(res).to.be.revertedWith("Walli: 2FA removal confirmation still pending from guardians");
            })

            it("Should finalise 2FA removal and addSession should revert with 'Walli: 2FA is not enabled ", async function () {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiate2FARemoval);

                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("confirm2FARemoval")
                }
                const res1 = await addr1.sendTransaction(tx1);
                await res1.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("confirm2FARemoval")
                }
                const res2 = await addr2.sendTransaction(tx2);
                await res2.wait();

                await time.increaseTo(await time.latest() + 5 * 24 * 60 * 60);
                const tx3 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("finalise2FARemoval")
                }
                const res3 = await addr1.sendTransaction(tx3);
                await res3.wait();

                const data = await ethers.provider.call({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("is2FAEnabled")
                })
                const is2FAEnabled = Walli__factory.createInterface().decodeFunctionResult("is2FAEnabled", data)[0] as boolean;
                expect(is2FAEnabled).to.be.false;

            });

            it("Should cancel 2FA removal and get2FARemoval should revert with 'Walli: No 2FA removal pending request' ", async function () {
                const { owner, proxy, proxyAddress, addr1, addr2, addr3, addr4, guardianArg1, guardianArg2, guardianArg3 } = await loadFixture(initiate2FARemoval);

                const tx1 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("cancel2FARemoval")
                }
                const res1 = await addr1.sendTransaction(tx1);
                await res1.wait();

                const tx2 = {
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("cancel2FARemoval")
                }
                const res2 = await addr2.sendTransaction(tx2);
                await res2.wait();


                const data = ethers.provider.call({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("get2FARemoval")
                });
                await expect(data).to.be.revertedWith("Walli: No 2FA removal pending request")

            });
        });


        describe("Validate User Op", function(){

            it("user op", async function(){
                const { proxyAddress, owner, walliShield, entryPoint, addr1, addr2, addr3, addr4 } = await loadFixture(deployWalli);
                
                const hash = "0x1c182092ffe049a1ef3b15667b6e5cc0d859192857e426f9082ab1f39b4706f6";
                const signature = await owner.signMessage(ethers.getBytes(hash));
                const userOp: UserOperationStruct = {
                    callData
                        :
                        "0xb8c51f42000000000000000000000000a9d0bde901fd895528b795fe89c5aab9457c39ec00000000000000000000000000000000000000000000000000005af3107a40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001388181f050c4394eb8f69b8e73ca2fdef69028f6a55840383af0e87ed2905f51531100000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000418eef117cff50c506c5f9354b9ce9bb832e26c99e3701acb7f9bca0dea37871b22b6f917e81f80463e691a148ffc8c225a7e3b820ccbc79bf9a4424f1c176a59b1b00000000000000000000000000000000000000000000000000000000000000",
callGasLimit
                        :
                        "0x125f7",
initCode
                        :
                        "0x",
maxFeePerGas
                        :
                        "0x59682f20",
maxPriorityFeePerGas
                        :
                        "0x59682f00",
nonce
                        :
                        "0x0",
paymasterAndData
                        :
                        "0x",
preVerificationGas
                        :
                        "0xc80f",
sender
                        :
                        "0x91fE5dCFa54179FD098476CE77941848A232FdC9",
signature
                        : signature,
                        // "0x80eb98b3d00158f3e7da0f3bc22208d525b2ae075bdc9af87108e72176437b2917fbe419d6d89fa30d0f6417a20335ad02e2f0079ffdd0732447d5e6551ad7621b",
verificationGasLimit
                        :
                        "0x1dcd4"
                }

                const tx = await entryPoint.sendTransaction({
                    to: proxyAddress,
                    data: Walli__factory.createInterface().encodeFunctionData("validateUserOp", [userOp, hash, 0n])
                })
                await tx.wait();
                console.log(tx.hash);

            })
        })


    })

})