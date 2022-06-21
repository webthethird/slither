from abc import ABC

import sha3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.detectors.proxy.proxy_features import ProxyFeatureExtraction
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.children.child_contract import ChildContract
from slither.core.declarations.structure import Structure
from slither.core.declarations.structure_contract import StructureContract
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

    def detect_mappings(self, proxy_features: ProxyFeatureExtraction, delegate: Variable):
        results = []
        proxy = proxy_features.contract
        """
        Check mapping types, i.e. delegate.type_from and delegate.type_to
        """
        if proxy_features.is_eternal_storage():
            info = [
                proxy,
                " uses Eternal Storage\n"
            ]
            json = self.generate_result(info)
            results.append(json)
        if isinstance(delegate.type, MappingType):
            if f"{delegate.type.type_from}" == "bytes4":  # and f"{delegate.type.type_to}" == "address":
                """
                Check to confirm that `msg.sig` is used as the key in the mapping
                """
                if proxy_features.is_mapping_from_msg_sig(delegate):
                    info = [
                        delegate,
                        " maps function signatures (i.e. `msg.sig`) to addresses where the functions"
                        " are implemented, suggesting that ",
                        proxy,
                        " uses a multiple implementation pattern such as EIP-1538 or EIP-2535.\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
                    """
                    Check if the mapping is stored in a struct, i.e. DiamondStorage for EIP-2535
                    """
                    if isinstance(delegate, StructureVariable):
                        struct = delegate.structure
                        if struct.name == "DiamondStorage":
                            if struct.canonical_name == "LibDiamond.DiamondStorage":
                                info = [
                                    delegate,
                                    " is stored in the DiamondStorage structure specified by EIP-2535: ",
                                    struct,
                                    " which is declared in the standard's LibDiamond library.\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)
                            elif isinstance(struct, StructureContract):
                                info = [
                                    delegate,
                                    " is stored in the DiamondStorage structure specified by EIP-2535: ",
                                    struct,
                                    " but not the one declared in the LibDiamond library. It is declared in ",
                                    struct.contract,
                                    "\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)
                            """
                            Search for the Loupe functions required by EIP-2535.
                            """
                            loupe_facets = proxy_features.find_diamond_loupe_functions()
                            if len(loupe_facets) == 4:
                                info = [
                                    f"The Loupe function {f} is located in {c}\n" for f,c in loupe_facets
                                ]
                                json = self.generate_result(info)
                                results.append(json)
                            """
                            Check if function for adding/removing/replacing functions (i.e. DiamondCut) added in constructor
                            to determine if the Diamond is actually upgradeable
                            """
                        else:
                            info = [
                                delegate,
                                " is declared as part of a user-defined structure: ",
                                struct,
                                " which is consistent with the Diamond Storage pattern but not EIP-2535\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                    else:
                        """
                        Mapping not stored in a struct
                        """
                else:
                    info = [
                        delegate,
                        " probably maps function signatures (i.e. the key is of type `bytes4`) to"
                        " addresses where the functions are implemented, but the detector could not"
                        " find the index access expression using `msg.sig` and cannot say for sure if ",
                        proxy,
                        " uses a multiple implementation pattern such as EIP-1538 or EIP-2535.\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
            else:
                info = [
                    delegate,
                    " is a mapping from type ",
                    str(delegate.type.type_from),
                    " to type ",
                    str(delegate.type.type_to),
                    "\n"
                ]
                json = self.generate_result(info)
                results.append(json)
        return results

    def detect_storage_slot(self, proxy_features: ProxyFeatureExtraction):
        print(f"detect_storage_slot: {proxy_features.contract}")
        results = []
        proxy = proxy_features.contract
        slot = proxy_features.find_impl_slot_from_sload()
        if slot is not None:
            print(f"slot is not None: {slot}")
            info = [
                proxy,
                " uses Unstructured Storage\n"
            ]
            json = self.generate_result(info)
            results.append(json)
            setter = proxy.proxy_implementation_setter
            if setter is None:
                """
                Use the getter instead
                """
                setter = proxy.proxy_implementation_getter
            else:
                print(f"Setter found in contract {setter.contract}")
            if setter.contract == proxy or setter.contract in proxy.inheritance:
                if slot == "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc":
                    info = [
                        proxy,
                        " implements EIP-1967: Standard Proxy Storage Slots\n"
                        "IMPLEMENTATION_SLOT == bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
                else:
                    info = [
                        proxy,
                        " looks like an early implementation of unstructured storage (i.e. ZeppelinOS)"
                        " using slot: ",
                        slot, "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
            elif setter.contract != proxy and proxy_features.proxy_only_contains_fallback():
                if slot == "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc":
                    info = [
                        proxy,
                        " implements EIP-1822 using the standard storage slot defined by ERC-1967: "
                        "IMPLEMENTATION_SLOT == bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1) "
                        "(OpenZeppelin UUPS implementation)\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)

                elif slot == "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7":
                    info = [
                        proxy,
                        " implements EIP-1822 (UUPS) with the storage slot = keccak256('PROXIABLE')\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
                else:
                    info = [
                        proxy,
                        " looks like an early implementation of unstructured storage (i.e. ZeppelinOS) "
                        "Using slot: ",
                        slot, "\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
        return results

    def detect_cross_contract_call(self, proxy_features: ProxyFeatureExtraction):
        results = []
        proxy = proxy_features.contract
        delegate = proxy_features.impl_address_variable
        is_cross_contract, call_exp, contract_type = proxy_features.impl_address_from_contract_call()
        if is_cross_contract:
            """
            is_cross_contract is a boolean returned by proxy_features.impl_address_from_contract_call()
            which indicates whether or not a cross contract call was found.
            exp is the CallExpression that was found, t is the type of the contract called.
            """
            info = [
                delegate,
                " value is retrieved from a function call to another contract: ",
                str(call_exp),
                "\n"
            ]
            json = self.generate_result(info)
            results.append(json)
            if isinstance(call_exp, CallExpression) and isinstance(contract_type, UserDefinedType):
                """
                We use the presence or absence of arguments in the CallExpression
                to classify the contract as a Registry or a Beacon.
                A Beacon should have no arguments, while a Registry should have at least one.
                """
                if len(call_exp.arguments) > 0 and str(call_exp.arguments[0]) != "":
                    rorb = "Registry"
                else:
                    rorb = "Beacon"
                info = [
                    contract_type.type,
                    f" appears to serve as a {rorb} contract for the proxy ",
                    proxy.name,
                    "\n"
                ]
                json = self.generate_result(info)
                results.append(json)
                """
                Check where the Registry/Beacon address comes from, 
                i.e. from a storage slot or a state variable
                """
                source = proxy_features.find_registry_address_source(call_exp)
                if source is not None:
                    if source.is_constant and str(source.type) == "bytes32":
                        info = [
                            "The address of ",
                            contract_type.type,
                            " appears to be loaded from the storage slot ",
                            source,
                            " which is ",
                            str(source.expression),
                            "\n"
                        ]
                    elif isinstance(source, StateVariable):
                        info = [
                            "The address of ",
                            contract_type.type,
                            " appears to be stored as a state variable: ",
                            source.canonical_name,
                            "\n"
                        ]
                        if source.is_constant:
                            info += [
                                source.name,
                                f" is constant, so the {rorb} address cannot be upgraded.\n"
                            ]
                        else:
                            setters = proxy.get_functions_writing_to_variable(source)
                            setters = [str(setter) for setter in setters if not setter.is_constructor]
                            if len(setters) > 0:
                                info += [
                                    source.name,
                                    " can be updated by the following function(s): ",
                                    str(setters),
                                    "\n"
                                ]
                            else:
                                info += [
                                    "Could not find setter for ",
                                    source.name,
                                    "\n"
                                ]
                    else:
                        info = [
                            "The address of ",
                            contract_type.type,
                            " comes from the value of ",
                            source,
                            "\n"
                        ]
                    json = self.generate_result(info)
                    results.append(json)
        return results

    def _detect(self):
        results = []
        for contract in self.contracts:
            proxy_features = ProxyFeatureExtraction(contract, self.compilation_unit)
            if proxy_features.is_upgradeable_proxy:
                proxy = contract
                delegate = proxy_features.impl_address_variable
                info = [proxy, " appears to ",
                        "maybe " if not proxy_features.is_upgradeable_proxy_confirmed else "",
                        "be an upgradeable proxy contract.\n"]
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
                            """
                            Check if the implementation address setter is in the proxy contract. 
                            """
                            if proxy.proxy_implementation_setter is not None:
                                if proxy.proxy_implementation_setter.contract == proxy:
                                    info = [
                                        "Implementation setter ",
                                        proxy.proxy_implementation_setter,
                                        " was found in the proxy contract.\n"
                                    ]
                                else:
                                    info = [
                                        "Implementation setter ",
                                        proxy.proxy_implementation_setter,
                                        " was found in another contract: ",
                                        proxy.proxy_implementation_setter.contract,
                                        "\n"
                                    ]
                                json = self.generate_result(info)
                                results.append(json)
                            """
                            Check if logic contract has same variable declared in same slot, i.e. Singleton/MasterCopy
                            """
                            idx, logic = proxy_features.is_impl_address_also_declared_in_logic()
                            if idx >= 0 and logic is not None:
                                if idx == 0:
                                    suffix = "st"
                                elif idx == 1:
                                    suffix = "nd"
                                elif idx == 2:
                                    suffix = "rd"
                                else:
                                    suffix = "th"
                                info = [
                                    "The state variable ",
                                    delegate,
                                    " is declared in both the proxy and the logic contract (",
                                    logic,
                                    f") in the {idx + 1}{suffix} position, i.e. storage slot {idx}."
                                    " This is akin to the GnosisSafeProxy, and is similar to Inherited Storage, as"
                                    " there is strong coupling between the storage layouts of the proxy and logic"
                                    " contracts.\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)

                        elif isinstance(delegate.type, MappingType):
                            """
                            Check for mapping results after the else block below, because we want 
                            to check for Eternal Storage regardless of the delegate variable type.
                            i.e. the implementation address may be stored as a StateVariable, but
                            the proxy could still use mappings to store all other variables.
                            """
                            info = [
                                proxy,
                                " stores implementation(s) in a mapping of type ",
                                delegate.type,
                                " declared in the proxy contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        else:
                            """
                            Do something else? 
                            Print result for debugging
                            """
                            info = [
                                proxy,
                                " stores implementation address in a state variable of type ",
                                delegate.type,
                                " declared in the proxy contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        """
                        Check for mappings regardless of delegate.type, 
                        in case EternalStorage is used for variables other than the implementation address.
                        """
                        map_results = self.detect_mappings(proxy_features, delegate)
                        for r in map_results:
                            results.append(r)
                    elif isinstance(delegate, LocalVariable):
                        """
                        Check where the local variable gets the value of the implementation address from, i.e., 
                        is it loaded from a storage slot, or by a call to a different contract, or something else?
                        """
                        print(f"{delegate} is a LocalVariable")
                        mapping, exp = ProxyFeatureExtraction.find_mapping_in_var_exp(delegate, proxy)
                        slot_results = self.detect_storage_slot(proxy_features)
                        if mapping is not None:
                            map_results = self.detect_mappings(proxy_features, mapping)
                            for r in map_results:
                                results.append(r)
                        if len(slot_results) > 0:
                            for r in slot_results:
                                results.append(r)
                        """
                        Check for call to a different contract in delegate.expression
                        """
                        cross_contract_results = self.detect_cross_contract_call(proxy_features)
                        for r in cross_contract_results:
                            results.append(r)
                    elif isinstance(delegate, StructureVariable):
                        """
                        Check the type of the structure variable, i.e. an address, a mapping, or something else
                        """
                        struct = delegate.structure
                        if f"{delegate.type}" == "address":
                            info = [
                                proxy,
                                " stores implementation address as a variable called ",
                                delegate,
                                " found in the structure called ",
                                struct,
                                " which is declared in the proxy contract\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        elif isinstance(delegate.type, MappingType):
                            info = [
                                proxy,
                                " stores implementation address in a mapping called ",
                                delegate,
                                " found in the structure called ",
                                struct,
                                " which is declared in the proxy contract\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            map_results = self.detect_mappings(proxy_features, delegate)
                            for r in map_results:
                                results.append(r)
                        else:
                            info = [
                                delegate,
                                " is a local variable of type ",
                                str(delegate.type),
                                " which is unexpected!\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                    else:
                        """
                        Should not be reachable, but print a result for debugging
                        """
                        info = [
                            delegate,
                            " is not a StateVariable, a LocalVariable, or a StructureVariable."
                            " This should not be possible!\n"
                        ]
                        json = self.generate_result(info)
                        results.append(json)
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
                                proxy_features.impl_address_location,
                                "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        elif isinstance(delegate.type, MappingType):
                            info = [
                                contract, " stores implementation(s) in a mapping declared in another contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        else:
                            """
                            Unexpected variable type
                            Print result for debugging
                            """
                            info = [
                                proxy,
                                " stores implementation address in a state variable of type ",
                                str(delegate.type),
                                " declared in another contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        map_results = self.detect_mappings(proxy_features, delegate)
                        for r in map_results:
                            results.append(r)
                        """
                        Check if proxy contract makes a call to impl_address_location contract to retrieve delegate
                        """
                        cross_contract_results = self.detect_cross_contract_call(proxy_features)
                        for r in cross_contract_results:
                            results.append(r)
                        """
                        Check if impl_address_location contract is inherited by any contract besides current proxy
                        """
                        for c in self.contracts:
                            if c == proxy or c == proxy_features.impl_address_location:
                                continue
                            if proxy_features.impl_address_location in proxy.inheritance and \
                                    proxy_features.impl_address_location in c.inheritance:
                                info = [
                                    proxy,
                                    " appears to be using Inherited Storage\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)

                    elif isinstance(delegate, LocalVariable):
                        """
                        Check where the local variable gets the value of the implementation address from, i.e., 
                        is it loaded from a storage slot, or by a call to a different contract, or something else?
                        """
                        mapping, exp = ProxyFeatureExtraction.find_mapping_in_var_exp(delegate,
                                                                                      delegate.function.contract)
                        slot_results = self.detect_storage_slot(proxy_features)
                        if mapping is not None:
                            map_results = self.detect_mappings(proxy_features, mapping)
                            for r in map_results:
                                results.append(r)
                        elif len(slot_results) > 0:
                            for r in slot_results:
                                results.append(r)
                        else:
                            """
                            Check for call to a different contract in delegate.expression
                            """
                            cross_contract_results = self.detect_cross_contract_call(proxy_features)
                            for r in cross_contract_results:
                                results.append(r)
                    elif isinstance(delegate, StructureVariable):
                        """
                        Check the type of the structure variable, i.e. an address, a mapping, or something else
                        """
                        struct = delegate.structure
                        if f"{delegate.type}" == "address":
                            info = [
                                proxy,
                                " stores implementation address as an address variable called ",
                                delegate,
                                " found in the structure called ",
                                struct,
                                "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        elif isinstance(delegate.type, MappingType):
                            info = [
                                proxy,
                                " stores implementation address in a mapping called ",
                                delegate,
                                " found in the structure called ",
                                struct,
                                " which is declared in the contract: ",
                                proxy_features.impl_address_location,
                                "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                            map_results = self.detect_mappings(proxy_features, delegate)
                            for r in map_results:
                                results.append(r)
                        else:
                            """
                            Unexpected variable type
                            Print result for debugging
                            """
                            info = [
                                proxy,
                                " stores implementation address in a variable of type ",
                                str(delegate.type),
                                " declared in a structure in another contract: ",
                                delegate, "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                    else:
                        """
                        Should not be reachable, but print a result for debugging
                        """
                        info = [
                            delegate,
                            " is not a StateVariable, a LocalVariable, or a StructureVariable."
                            " This should not be possible!\n"
                        ]
                        json = self.generate_result(info)
                        results.append(json)
                """
                Check if the proxy is transparent, i.e., if all external functions other than
                the fallback and receive are only callable by a specific address, and whether 
                the fallback and receive functions are only callable by addresses other than 
                the same specific address
                """
                is_transparent, admin_str = proxy_features.external_functions_require_specific_sender()
                if is_transparent:
                    info = [
                        proxy,
                        " uses the Transparent Proxy pattern\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
                """
                
                """
                has_checks, func_exp_list = proxy_features.has_compatibility_checks()
                info = []
                if not has_checks:
                    funcs_missing_check = [func for func, check in func_exp_list if check is None]
                    for func in funcs_missing_check:
                        info += [
                            "Missing compatibility check in ",
                            func, "\n"
                        ]
                elif len(func_exp_list) == 0:
                    info = ["Could not find any setter functions in which to look for compatibility checks.\n"]
                else:
                    info = ["Found the following compatibility checks in all upgrade functions: \n"]
                    for func, exp in func_exp_list:
                        info += [
                            "In ", func, ": ", str(exp), "\n"
                        ]
                if len(info) > 0:
                    json = self.generate_result(info)
                    results.append(json)
            elif contract.is_proxy:
                """
                Contract is either a non-upgradeable proxy, or upgradeability could not be determined
                """
                info = [contract, " appears to be a proxy contract, but it doesn't seem to be upgradeable.\n"]
                json = self.generate_result(info)
                results.append(json)
        return results
