from abc import ABC

import sha3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.detectors.proxy.proxy_features import ProxyFeatureExtraction
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.children.child_contract import ChildContract
from slither.core.declarations.structure import Structure
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.structure_variable import StructureVariable
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.literal import Literal
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.expression_typed import ExpressionTyped
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType


class ProxyPatterns(AbstractDetector, ABC):
    ARGUMENT = "proxy-patterns"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = "Proxy contract does not conform to any known standard"
    WIKI = "https://github.com/crytic/slither/wiki/Upgradeability-Checks#proxy-patterns"
    WIKI_TITLE = "Proxy Patterns"

    # region wiki_description
    WIKI_DESCRIPTION = """
Determine whether an upgradeable proxy contract conforms to any known proxy standards, i.e. OpenZeppelin, UUPS, Diamond 
Multi-Facet Proxy, etc.
"""
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Proxy{
    address logicAddress;

    function() payable {
        logicAddress.delegatecall(msg.data)
    }
}

contract Logic{
    uint variable1;
}
```
The new version, `V2` does not contain `variable1`. 
If a new variable is added in an update of `V2`, this variable will hold the latest value of `variable2` and
will be corrupted.
"""
    # endregion wiki_exploit_scenario

    # region wiki_recommendation
    WIKI_RECOMMENDATION = """
It is better to use one of the common standards for upgradeable proxy contracts. Consider EIP-1967, EIP-1822, EIP-2523, 
or one of the proxy patterns developed by OpenZeppelin.
"""

    # endregion wiki_recommendation

    def _detect(self):
        results = []
        for contract in self.contracts:
            proxy_features = ProxyFeatureExtraction(contract, self.compilation_unit)
            if proxy_features.is_upgradeable_proxy:
                proxy = contract
                delegate = proxy_features.impl_address_variable
                info = [proxy, " appears to ",
                        "maybe " if not proxy_features.is_upgradeable_proxy_confirmed else "",
                        "be an upgradeable proxy contract.\nIt delegates to a variable of type ",
                        f"{delegate.type} called {delegate.name}.\n"]
                json = self.generate_result(info)
                results.append(json)
                """
                Check location of implementation address, i.e. contract.delegate_variable.
                Could be located in proxy contract or in a different contract.
                """
                if proxy_features.impl_address_location == proxy:
                    """
                    Check the scope of the implementation address variable,
                    i.e., StateVariable or LocalVariable.
                    """
                    if isinstance(delegate, StateVariable):
                        """
                        Check the type of the state variable, i.e. an address, a mapping, or something else
                        """
                        if f"{delegate.type}" == "address":
                            info = [
                                proxy,
                                " stores implementation address as a state variable: ",
                                delegate,
                                "\nAvoid declaring state variables in the proxy. Better to use a standard storage slot,"
                                " e.g. as proposed in EIP-1967, EIP-1822, EIP-2535 or another well-audited pattern.\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)

                        elif isinstance(delegate, MappingType):
                            info = [
                                proxy, " stores implementation(s) in a mapping declared in the proxy contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            """
                            Check mapping types, i.e. delegate.type_from and delegate.type_to
                            """
                            if proxy_features.is_eternal_storage():
                                info = [
                                    proxy,
                                    " appears to be Eternal Storage\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)
                        else:
                            """
                            Do something else? 
                            Print result for debugging
                            """
                    elif isinstance(delegate, LocalVariable):
                        """
                        Check where the local variable gets the value of the implementation address from, i.e., 
                        is it loaded from a storage slot, or by a call to a different contract, or something else?
                        """
                    else:
                        """
                        Should not be reachable, but print a result for debugging
                        """
                else:   # Location of delegate is in a different contract
                    info = [delegate, " was found in a different contract: ",
                            proxy_features.impl_address_location, "\n"]
                    json = self.generate_result(info)
                    results.append(json)
                    """
                    Check the scope of the implementation address variable,
                    i.e., StateVariable or LocalVariable.
                    """
                    if isinstance(delegate, StateVariable):
                        """
                        Check the type of the state variable, i.e. an address, a mapping, or something else
                        """
                        if f"{delegate.type}" == "address":
                            info = [
                                proxy,
                                " stores implementation address as a state variable called ",
                                delegate,
                                " which is declared in the contract: ",
                                proxy_features.impl_address_location
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            """
                            Check if impl_address_location contract is inherited by any contract besides current proxy
                            """
                            for c in self.contracts:
                                if c == proxy or c == proxy_features.impl_address_location:
                                    continue
                                if proxy_features.impl_address_location in proxy.inheritance and \
                                        proxy_features.impl_address_location in c.inheritance:
                                    info = [
                                        proxy_features.impl_address_location,
                                        " appears to be Inherited Storage\n"
                                    ]
                                    json = self.generate_result(info)
                                    results.append(json)
                        elif isinstance(delegate.type, MappingType):
                            info = [
                                contract, " stores implementation(s) in a mapping declared in the proxy contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            """
                            Check mapping types, i.e. delegate.type_from and delegate.type_to
                            """
                            if proxy_features.is_eternal_storage():
                                info = [
                                    proxy_features.impl_address_location,
                                    " appears to be Eternal+Inherited Storage\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)

                    elif isinstance(delegate, LocalVariable):
                        """
                        Check where the local variable gets the value of the implementation address from, i.e., 
                        is it loaded from a storage slot, or by a call to a different contract, or something else?
                        """
                        if proxy_features.get_slot_loaded is not None:
                            info = [
                                proxy,
                                " appears to be Unstructured Storage\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            if proxy_features.get_slot_loaded() == "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc":

                                setter = proxy_features.contract.proxy_implementation_setter
                                if isinstance(setter, ChildContract):
                                    if setter.contract == proxy:
                                        info = [
                                            " EIP-1967\n"
                                        ]
                                        json = self.generate_result(info)
                                        results.append(json)
                        else:
                            """
                            Do something else
                            """
                    else:
                        """
                        Should not be reachable, but print a result for debugging
                        """
                """
                Check if proxy contains external functions 
                """

            elif contract.is_proxy:
                """
                Contract is either a non-upgradeable proxy, or upgradeability could not be determined
                """
                info = [contract, " appears to be a proxy contract, but it doesn't seem to be upgradeable.\n"]
                json = self.generate_result(info)
                results.append(json)
        return results
