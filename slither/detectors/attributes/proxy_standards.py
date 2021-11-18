from abc import ABC

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.expressions.identifier import Identifier
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.expression_typed import ExpressionTyped
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.member_access import MemberAccess

def find_slot_in_setter_asm(
        inline_asm: Union[str, Dict],
        delegate: LocalVariable
) -> Optional[str]:
    slot = None
    if "AST" in inline_asm and isinstance(inline_asm, Dict):
        for statement in inline_asm["AST"]["statements"]:
            if statement["nodeType"] == "YulExpressionStatement":
                statement = statement["expression"]
            if statement["nodeType"] == "YulVariableDeclaration":
                statement = statement["value"]
            if statement["nodeType"] == "YulFunctionCall":
                if statement["functionName"]["name"] == "sstore":
                    if statement["arguments"][1] == delegate.name:
                        slot = statement["arguments"][0]
    else:
        asm_split = inline_asm.split("\n")
        for asm in asm_split:
            if "sstore" in asm:
                params = asm.split("(")[1].strip(")").split(", ")
                slot = params[0]
    return slot


class ProxyStandards(AbstractDetector, ABC):
    ARGUMENT = "proxy-standards"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.MEDIUM

    HELP = "Proxy contract does not conform to any known standard"
    WIKI = "https://github.com/crytic/slither/wiki/Upgradeability-Checks#non-standard-proxy"
    WIKI_TITLE = "Non-Standard Proxy"

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
        storage_inheritance_index = None    # Use to ensure
        for contract in self.contracts:
            if contract.is_upgradeable_proxy:
                proxy = contract
                info = [proxy, " appears to be an upgradeable proxy contract.\n"]
                json = self.generate_result(info)
                results.append(json)
                delegate = proxy.delegates_to
                print(proxy.name + " delegates to variable of type " + str(delegate.type) + " called " + delegate.name)
                lib_diamond = proxy.compilation_unit.get_contract_from_name("LibDiamond")
                ierc_1538 = proxy.compilation_unit.get_contract_from_name("IERC1538")
                if lib_diamond is not None and lib_diamond.get_structure_from_name("DiamondStorage") is not None:
                    info = [proxy, " appears to be an EIP-2535 Diamond Proxy: This is a WIP.\n"]
                    json = self.generate_result(info)
                    results.append(json)
                elif ierc_1538 is not None and ierc_1538 in proxy.inheritance:
                    info = [proxy, " appears to be an EIP-1538 Transparent Proxy:\nThis EIP has been "
                                   "withdrawn and replaced with EIP-2535: Diamonds, Multi-Facet Proxy\n"]
                    json = self.generate_result(info)
                    results.append(json)
                elif isinstance(delegate, StateVariable):
                    print("delegate.contract = " + str(delegate.contract) + "\nproxy = " + str(proxy))
                    if delegate.contract == proxy:
                        info = [
                            proxy,
                            " stores implementation as state variable: ",
                            delegate,
                            "\nAvoid variables in the proxy. Better to use a standard storage slot, e.g. as proposed in ",
                            "EIP-1967, EIP-1822, Unstructured Storage, Eternal Storage or another well-audited pattern.\n"
                        ]
                        json = self.generate_result(info)
                        results.append(json)
                    else:
                        print("State variable " + delegate.name + " is in the inherited contract: "
                              + delegate.contract.name)
                        for idx, c in enumerate(proxy.inheritance_reverse):
                            if idx == 0:
                                suffix = "st"
                            elif idx == 1:
                                suffix = "nd"
                            elif idx == 2:
                                suffix = "rd"
                            else:
                                suffix = "th"
                            if c == delegate.contract:
                                info = [
                                    proxy,
                                    " stores implementation as state variable called ",
                                    delegate,
                                    " which is located in the inherited contract called ",
                                    c,
                                    "\nIf this is a storage contract which is shared with the logic contract, it is"
                                    " essential that both have the same order of inheritance, i.e. the storage contract"
                                    " must be the ",
                                    str(idx + 1),
                                    suffix,
                                    " contract inherited, and any preceding inheritances must also be identical.\n"
                                ]
                                json = self.generate_result(info)
                                results.append(json)
                elif isinstance(delegate, LocalVariable) and delegate.location is not None \
                        and "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7" in delegate.location:
                    print(proxy.name + " appears to be an EIP-1822 proxy. Looking for Proxiable contract.")
                    proxiable = proxy.compilation_unit.get_contract_from_name("Proxiable")
                    if proxiable is not None:
                        setter = proxiable.get_function_from_signature("updateCodeAddress(address)")
                        if setter is not None:
                            print("Found implementation setter " + setter.signature_str
                                  + " in contract " + proxiable.name)
                            for c in proxy.compilation_unit.contracts:
                                if c == proxiable:
                                    continue
                                if proxiable in c.inheritance:
                                    print("Contract " + c.name + " inherits " + proxiable.name)
                                    proxiable = c
                            info = [
                                proxy,
                                " appears to be an EIP-1822 Universal Upgradeable Proxy:\nThis proxy doesn't contain"
                                " its own upgrade logic - it is in the logic contract which must inherit Proxiable.\n",
                                proxiable,
                                " appears to be the logic contract used by this proxy."
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        else:
                            info = [
                                proxy,
                                " appears to be an EIP-1822 Universal Upgradeable Proxy:\nHowever, the Proxiable "
                                "contract ",
                                proxiable,
                                " does not appear to contain the expected implementation setter, updateCodeAddress()."
                                " If this is indeed an EIP-1822 logic contract, then it may no longer be upgradeable!\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                    else:
                        info = [
                            proxy,
                            " appears to be an EIP-1822 Universal Upgradeable Proxy:\nThis proxy doesn't contain"
                            " its own upgrade logic - it is in the logic contract which must inherit Proxiable.\n",
                            "However, the Proxiable contract could not be found in the compilation unit.\n"
                        ]
                        json = self.generate_result(info)
                        results.append(json)
                else:
                    constants = [variable for variable in proxy.variables if variable.is_constant]
                    setter = proxy.proxy_implementation_setter
                    slot = None
                    if setter is not None:
                        if isinstance(setter, FunctionContract) and setter.contract != proxy:
                            info = [
                                "Implementation setter for proxy contract ",
                                proxy,
                                " is located in another contract:\n",
                                setter,
                                "\n"
                            ]
                            json = self.generate_result(info)
                            results.append(json)
                        if isinstance(delegate, LocalVariable):
                            exp = delegate.expression
                            if exp is not None:
                                print(exp)
                            else:
                                for node in setter.all_nodes():
                                    # print(str(node.type))
                                    if node.type == NodeType.VARIABLE:
                                        exp = node.variable_declaration.expression
                                        if exp is not None and isinstance(exp, Identifier):
                                            slot = str(exp.value.expression)
                                            break
                                    # elif node.type == NodeType.EXPRESSION:
                                    #     print(node.expression)
                                    elif node.type == NodeType.ASSEMBLY:
                                        slot = find_slot_in_setter_asm(node.inline_asm, delegate)
                                        break
                                if slot is not None:
                                    print(slot)
                    else:
                        getter = proxy.proxy_implementation_getter
                        exp = None
                        ext_call = None
                        for node in getter.all_nodes():
                            # print(node.type)
                            exp = node.expression
                            # print(exp)
                            # if node.expression is not None:
                            if node.type == NodeType.RETURN and isinstance(exp, CallExpression):
                                print("This return node is a CallExpression")
                                if isinstance(exp.called, MemberAccess):
                                    print("The CallExpression is for MemberAccess")
                                    exp = exp.called
                                    break
                                elif isinstance(node.expression, Identifier):
                                    print("This return node is a variable Identifier")
                                elif isinstance(node.expression, ExpressionTyped):
                                    print(node.expression.type)
                            elif node.type == NodeType.EXPRESSION and isinstance(exp, AssignmentOperation):
                                left = exp.expression_left
                                right = exp.expression_right
                                if isinstance(left, Identifier):
                                    print("Left: Identifier " + str(left.type))
                                if isinstance(right, CallExpression):
                                    print("Right: " + str(right.called))
                                    if "call" in str(right):
                                        exp = right.called
                                        break
                        if isinstance(exp, MemberAccess):
                            # Getter calls function of another contract in return expression
                            call_exp = exp.expression
                            print(call_exp)
                            call_function = exp.member_name
                            call_contract = None
                            call_type = None
                            if isinstance(call_exp, TypeConversion):
                                print("The getter calls a function from a contract of type " + str(call_exp.type))
                                call_type = call_exp.type
                            elif isinstance(call_exp, Identifier):
                                val = call_exp.value
                                if str(val.type) == "address" and val.is_constant:
                                    info = [
                                        "Implementation getter for proxy contract ",
                                        proxy,
                                        " appears to make a call to a constant address variable: ",
                                        val,
                                        "\nWithout the Contract associated with this we cannot confirm upgradeability\n"
                                    ]
                                    if "beacon" in val.name.lower():
                                        info.append("However, it appears to be the address of an Upgrade Beacon\n")
                                    json = self.generate_result(info)
                                    results.append(json)
                            if call_type is not None:
                                call_contract = proxy.compilation_unit.get_contract_from_name(str(call_type))
                                if call_contract is not None:
                                    print("\nFound contract called by proxy: " + call_contract.name)
                                    interface = None
                                    if call_contract.is_interface:
                                        interface = call_contract
                                        call_contract = None
                                        print("It's an interface\nLooking for a contract that implements the interface "
                                              + interface.name)
                                        for c in proxy.compilation_unit.contracts:
                                            if interface in c.inheritance:
                                                print(c.name + " inherits the interface " + interface.name)
                                                call_contract = c
                                                break
                                        if call_contract is None:
                                            print("Could not find a contract that inherits " + interface.name + "\n"
                                                  + "Looking for a contract with " + call_function)
                                            for c in self.compilation_unit.contracts:
                                                has_called_func = False
                                                if c == interface:
                                                    continue
                                                for f in interface.functions_signatures:
                                                    if exp.member_name not in f:
                                                        continue
                                                    if f in c.functions_signatures:
                                                        print(c.name + " has function " + f + " from interface")
                                                        has_called_func = True
                                                        break
                                                if has_called_func:
                                                    print(c.name + " contains the implementation getter")
                                                    call_contract = c
                                                    break
                                        if call_contract is None:
                                            print("Could not find a contract that implements " + exp.member_name
                                                  + " from " + interface.name + ":")
                                        else:
                                            print("Looking for implementation setter in " + call_contract.name)
                                            setter = proxy.find_setter_in_contract(call_contract, delegate,
                                                                                   proxy.proxy_impl_storage_offset,
                                                                                   True)
                                            if setter is not None:
                                                print("\nImplementation set by function: " + setter.name
                                                      + " in contract: " + call_contract.name)
                                                info = [
                                                    "Implementation setter for proxy contract ",
                                                    proxy,
                                                    " is located in another contract:\n",
                                                    setter,
                                                    "\n"
                                                ]
                                                json = self.generate_result(info)
                                                results.append(json)
                                                break
                                    if call_contract is not None and not call_contract.is_interface:
                                        contains_getter = False
                                        contains_setter = False
                                        implementation = None
                                        for f in call_contract.functions:
                                            if f.name == exp.member_name:
                                                for v in f.returns:
                                                    if str(v.type) == "address":
                                                        print("Found getter " + f.name + " in " + call_contract.name)
                                                        contains_getter = True
                                                        call_function = f
                                                        break
                                                if contains_getter:
                                                    for v in f.variables_read:
                                                        if isinstance(v, StateVariable):
                                                            implementation = v
                                                            break
                                                    break
                                        if contains_getter:
                                            print("Looking for implementation setter in " + call_contract.name)
                                            setter = proxy.find_setter_in_contract(call_contract, delegate,
                                                                                   proxy.proxy_impl_storage_offset,
                                                                                   True)
                                            if setter is not None:
                                                print("Found implementation setter ")
                                                info = [
                                                    "Implementation setter for proxy contract ",
                                                    proxy,
                                                    " is located in another contract:\n",
                                                    setter,
                                                    "\n"
                                                ]
                                                json = self.generate_result(info)
                                                results.append(json)
                                                break
                                            else:
                                                info = [
                                                    "Could not find implementation setter for proxy contract ",
                                                    proxy,
                                                    " which should be located in another contract:\n",
                                                    call_contract,
                                                    "\n"
                                                ]
                                                json = self.generate_result(info)
                                                results.append(json)
                                else:
                                    print("Could not find a contract called " + str(call_type) + " in compilation unit")
                        elif isinstance(exp, CallExpression):
                            print("Not member access, just a CallExpression\n" + str(exp))
                            exp = exp.called
                            if isinstance(exp, MemberAccess):
                                print(exp.type)
                            if "." in str(exp):
                                target = str(exp).split(".")[0]
            elif contract.is_proxy:
                info = [contract, " appears to be a proxy contract, but it doesn't seem to be upgradeable.\n"]
                json = self.generate_result(info)
                results.append(json)

        return results
