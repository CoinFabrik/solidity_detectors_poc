// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;

contract InsecureEtherVault {
    mapping (address => uint256) private userBalances;
    uint256 constant stateVariable = 55;
    uint256 constant stateVariableany = stateVariable + 29;
    uint256 otherVar = 65465;

    function deposit() external payable {
        uint256 myval = 16 / 2 + 65 -25;
        uint256 e = myval - 48;
        uint256 f = 2 / e;
        uint256 ko = 88 + e;
        userBalances[msg.sender] += msg.value;
        if (e == 15){
            myval = 2;
        }
        else{
            myval = 0;
        }
        e = ko / myval;
        f = stateVariable + 56;
        if (e == 22) {
            f = 58 + stateVariable;
            }
        else {
            f = stateVariable;
        }
        ko = f *6;
        myval = otherVar;
    }

    function withdraw(uint256 _amount) external {
        uint256 b = 6542345;
        uint256 a = 324;
        uint256 r = otherVar;
        uint256 balance = getUserBalance(msg.sender);
        require(balance - _amount >= 0, "Insufficient balance");
        otherVar = balance;

        userBalances[msg.sender] -= _amount;
        
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Failed to send Ether");
    }

    function getEtherBalance() external returns (uint256) {
        uint256 localModified = stateVariable + 85;
        uint256 anotherzero = 89 / localModified;
        uint256 raiseserror = 2 / anotherzero;
        otherVar = localModified + 7;
        return address(this).balance;
    }

    function getUserBalance(address _user) public view returns (uint256) {
        return userBalances[_user];
    }
}

/*
Arithmetic - Integer Underflow 

A simple vault in which users can deposit Ether, withdraw Ether and check their
balances. Vulnerability is in withdraw function, line 13.

Adapted from https://github.com/serial-coder/solidity-security-by-example/tree/main/01_integer_underflow
*/
