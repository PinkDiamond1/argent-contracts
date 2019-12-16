pragma solidity ^0.5.4;

import "../../modules/maker/MakerV2Manager.sol";

contract MockVat {
    function hope(address) external {}
}
contract MockTub {
    function gov() external pure returns (GemLike) { return GemLike(address(0)); }
}
contract MockJoin {
    constructor () public { vat = new MockVat(); }
    function ilk() external pure returns (bytes32) { return bytes32(0); }
    function gem() external pure returns (GemLike) { return GemLike(address(0)); }
    function dai() external pure returns (GemLike) { return GemLike(address(0)); }
    MockVat public vat;
}

/**
 * @title MockScdMcdMigration
 * @dev Mock contract needed to deploy the MakerV2Manager contract
 */
contract MockScdMcdMigration {

    MockJoin public saiJoin;
    MockJoin public daiJoin;
    MockJoin public wethJoin;
    MockTub public tub;
    ManagerLike public cdpManager;

    constructor (address _daiJoin) public {
        daiJoin = (_daiJoin != address(0)) ? MockJoin(daiJoin) : new MockJoin();
        saiJoin = new MockJoin();
        wethJoin = new MockJoin();
        tub = new MockTub();
    }
}