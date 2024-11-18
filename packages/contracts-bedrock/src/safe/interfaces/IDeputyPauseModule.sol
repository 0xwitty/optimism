// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { GnosisSafe as Safe } from "safe-contracts/GnosisSafe.sol";
import { ISemver } from "src/universal/interfaces/ISemver.sol";
import { IDeputyGuardianModule } from "./IDeputyGuardianModule.sol";

interface IDeputyPauseModule is ISemver {
    error DeputyPauseModule_ExecutionFailed(string);
    error DeputyPauseModule_Unauthorized();
    error DeputyPauseModule_NonceAlreadyUsed();

    event Paused(string identifier);

    function version() external view returns (string memory);
    function __constructor__(
        Safe _foundationSafe,
        IDeputyGuardianModule _deputyGuardianModule,
        address _deputy
    )
        external;
    function foundationSafe() external view returns (Safe foundationSafe_);
    function deputyGuardianModule() external view returns (IDeputyGuardianModule deputyGuardianModule_);
    function deputy() external view returns (address deputy_);
    function usedNonces(bytes32) external view returns (bool);
    function pause(bytes32 _nonce, bytes memory _signature) external;
}
