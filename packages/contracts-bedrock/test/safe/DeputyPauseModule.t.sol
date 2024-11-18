// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// Testing
import { CommonTest } from "test/setup/CommonTest.sol";
import { ForgeArtifacts, Abi } from "scripts/libraries/ForgeArtifacts.sol";
import { GnosisSafe as Safe } from "safe-contracts/GnosisSafe.sol";
import "test/safe-tools/SafeTestTools.sol";

// Scripts
import { DeployUtils } from "scripts/libraries/DeployUtils.sol";

// Libraries
import { ECDSA } from "@solady/utils/ECDSA.sol";

// Interfaces
import { IDeputyGuardianModule } from "src/safe/interfaces/IDeputyGuardianModule.sol";
import { IDeputyPauseModule } from "src/safe/interfaces/IDeputyPauseModule.sol";

/// @title DeputyPauseModule_TestInit
/// @notice Base test setup for the DeputyPauseModule.
contract DeputyPauseModule_TestInit is CommonTest, SafeTestTools {
    using SafeTestLib for SafeInstance;

    event ExecutionFromModuleSuccess(address indexed);

    IDeputyPauseModule deputyPauseModule;
    IDeputyGuardianModule deputyGuardianModule;
    SafeInstance securityCouncilSafeInstance;
    SafeInstance foundationSafeInstance;
    address deputy;
    uint256 deputyKey;

    /// @notice Sets up the test environment.
    function setUp() public virtual override {
        super.setUp();

        // Set up 20 keys.
        (, uint256[] memory keys) = SafeTestLib.makeAddrsAndKeys("DeputyPauseModule_test_", 20);

        // Split into two sets of 10 keys.
        uint256[] memory keys1 = new uint256[](10);
        uint256[] memory keys2 = new uint256[](10);
        for (uint256 i; i < 10; i++) {
            keys1[i] = keys[i];
            keys2[i] = keys[i + 10];
        }

        // Create a Security Council Safe with 10 owners.
        securityCouncilSafeInstance = _setupSafe(keys1, 10);

        // Create a Foundation Safe with 10 different owners.
        foundationSafeInstance = _setupSafe(keys2, 10);

        // Set the Security Council Safe as the Guardian of the SuperchainConfig.
        vm.store(
            address(superchainConfig),
            superchainConfig.GUARDIAN_SLOT(),
            bytes32(uint256(uint160(address(securityCouncilSafeInstance.safe))))
        );

        // Create a DeputyGuardianModule and set the Foundation Safe as the Deputy Guardian.
        deputyGuardianModule = IDeputyGuardianModule(
            DeployUtils.create1({
                _name: "DeputyGuardianModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyGuardianModule.__constructor__,
                        (securityCouncilSafeInstance.safe, superchainConfig, address(foundationSafeInstance.safe))
                    )
                )
            })
        );

        // Enable the DeputyGuardianModule on the Security Council Safe.
        securityCouncilSafeInstance.enableModule(address(deputyGuardianModule));

        // Create the deputy for the DeputyPauseModule.
        (deputy, deputyKey) = makeAddrAndKey("deputy");

        // Create the DeputyPauseModule.
        deputyPauseModule = IDeputyPauseModule(
            DeployUtils.create1({
                _name: "DeputyPauseModule",
                _args: DeployUtils.encodeConstructor(
                    abi.encodeCall(
                        IDeputyPauseModule.__constructor__, (foundationSafeInstance.safe, deputyGuardianModule, deputy)
                    )
                )
            })
        );

        // Enable the DeputyPauseModule on the Foundation Safe.
        foundationSafeInstance.enableModule(address(deputyPauseModule));
    }

    /// @notice Generates a signature to trigger a pause.
    /// @param _nonce The nonce to use.
    /// @param _privateKey The private key to use to sign the message.
    /// @return Generated signature.
    function makePauseSignature(bytes32 _nonce, uint256 _privateKey) internal pure returns (bytes memory) {
        bytes32 message = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, message);
        return abi.encodePacked(r, s, v);
    }
}

/// @title DeputyPauseModule_Getters_Test
/// @notice Tests that the getters work.
contract DeputyPauseModule_Getters_Test is DeputyPauseModule_TestInit {
    /// @notice Tests that the getters work.
    function test_getters_works() external view {
        assertEq(address(deputyPauseModule.foundationSafe()), address(foundationSafeInstance.safe));
        assertEq(address(deputyPauseModule.deputyGuardianModule()), address(deputyGuardianModule));
        assertEq(deputyPauseModule.deputy(), deputy);
    }
}

/// @title DeputyPauseModule_Pause_Test
/// @notice Tests that the pause() function works.
contract DeputyPauseModule_Pause_Test is DeputyPauseModule_TestInit {
    /// @notice Tests that pause() successfully pauses when called by the deputy.
    /// @param _nonce The nonce to use.
    function testFuzz_pause_anyNonce_succeeds(bytes32 _nonce) external {
        vm.expectEmit(address(superchainConfig));
        emit Paused("Deputy Guardian");

        vm.expectEmit(address(securityCouncilSafeInstance.safe));
        emit ExecutionFromModuleSuccess(address(deputyGuardianModule));

        vm.expectEmit(address(deputyGuardianModule));
        emit Paused("Deputy Guardian");

        vm.expectEmit(address(foundationSafeInstance.safe));
        emit ExecutionFromModuleSuccess(address(deputyPauseModule));

        vm.expectEmit(address(deputyPauseModule));
        emit Paused("Pause Deputy");

        bytes memory signature = makePauseSignature(_nonce, deputyKey);
        deputyPauseModule.pause(_nonce, signature);
        assertEq(superchainConfig.paused(), true);
    }
}

/// @title DeputyPauseModule_Pause_TestFail
/// @notice Tests that the pause() function reverts when it should.
contract DeputyPauseModule_Pause_TestFail is DeputyPauseModule_TestInit {
    /// @notice Tests that pause() reverts when called by an address other than the deputy.
    /// @param _privateKey The private key to use to sign the message.
    function testFuzz_pause_notDeputy_reverts(uint256 _privateKey) external {
        // Make sure that the private key is not the deputy's private key.
        vm.assume(_privateKey != deputyKey);

        // Make sure that the private key is in the range of a valid secp256k1 private key.
        _privateKey = bound(_privateKey, 1, SECP256K1_ORDER - 1);

        // Expect a revert.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_Unauthorized.selector));
        bytes32 nonce = keccak256("nonce");
        bytes memory signature = makePauseSignature(nonce, _privateKey);
        deputyPauseModule.pause(nonce, signature);
    }

    /// @notice Tests that pause() reverts when the nonce has already been used.
    /// @param _nonce The nonce to use.
    function testFuzz_pause_nonceAlreadyUsed_reverts(bytes32 _nonce) external {
        // Pause once.
        bytes memory signature = makePauseSignature(_nonce, deputyKey);
        deputyPauseModule.pause(_nonce, signature);

        // Unpause.
        vm.prank(address(securityCouncilSafeInstance.safe));
        superchainConfig.unpause();

        // Expect that the nonce is now used.
        assertEq(deputyPauseModule.usedNonces(_nonce), true);

        // Pause again.
        vm.expectRevert(abi.encodeWithSelector(IDeputyPauseModule.DeputyPauseModule_NonceAlreadyUsed.selector));
        deputyPauseModule.pause(_nonce, signature);
    }

    /// @notice Tests that the error message is returned when the call to the safe reverts.
    function test_pause_targetReverts_reverts() external {
        // Make sure that the SuperchainConfig pause() reverts.
        vm.mockCallRevert(
            address(superchainConfig),
            abi.encodePacked(superchainConfig.pause.selector),
            "SuperchainConfig: pause() reverted"
        );

        // Note that the error here will be somewhat awkwardly double-encoded because the
        // DeputyGuardianModule will encode the revert message as an ExecutionFailed error and then
        // the DeputyPauseModule will re-encode it as another ExecutionFailed error.
        vm.expectRevert(
            abi.encodeWithSelector(
                IDeputyPauseModule.DeputyPauseModule_ExecutionFailed.selector,
                string(
                    abi.encodeWithSelector(
                        IDeputyGuardianModule.ExecutionFailed.selector, "SuperchainConfig: pause() reverted"
                    )
                )
            )
        );
        bytes32 nonce = keccak256("nonce");
        bytes memory signature = makePauseSignature(nonce, deputyKey);
        deputyPauseModule.pause(nonce, signature);
    }
}
