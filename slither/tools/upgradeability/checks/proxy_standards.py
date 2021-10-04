from slither.tools.upgradeability.checks.abstract_checks import (
    CheckClassification,
    AbstractCheck,
)
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.expressions.identifier import Identifier
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.expression_typed import ExpressionTyped


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


class NonStandardProxy(AbstractCheck):
    ARGUMENT = "non-standard-proxy"
    IMPACT = CheckClassification.INFORMATIONAL

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
contract V1{
    uint variable1;
    uint variable2;
}

contract V2{
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

    REQUIRE_CONTRACT = True
    REQUIRE_PROXY = True

    def _check(self):
        proxy: Contract = self.proxy
        results = []

        if proxy.is_upgradeable_proxy:
            delegate = proxy.delegates_to
            if delegate is not None:
                print(proxy.name + " delegates to variable of type " + str(delegate.type) + " called " + delegate.name)
                if str(delegate.type) == "mapping(bytes4 => address)":
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
                    info = [
                        proxy,
                        " stores implementation as state variable: ",
                        delegate,
                        "\nAvoid variables in the proxy. Better to use a standard storage slot, e.g. as proposed in ",
                        "EIP-1967, EIP-1822, or OpenZeppelin's Unstructured Storage.\n"
                    ]
                    json = self.generate_result(info)
                    results.append(json)
                else:
                    constants = [variable for variable in proxy.variables if variable.is_constant]
                    setter = proxy.proxy_implementation_setter
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
                        slot = None
                        if isinstance(delegate, LocalVariable):
                            exp = delegate.expression
                            if exp is not None:
                                print(exp)
                            else:
                                for node in setter.all_nodes():
                                    print(str(node.type))
                                    if node.type == NodeType.VARIABLE:
                                        exp = node.variable_declaration.expression
                                        if exp is not None and isinstance(exp, Identifier):
                                            slot = str(exp.value.expression)
                                            break
                                    elif node.type == NodeType.EXPRESSION:
                                        print(node.expression)
                                    elif node.type == NodeType.ASSEMBLY:
                                        slot = find_slot_in_setter_asm(node.inline_asm, delegate)
                                        break
                                if slot is not None:
                                    print(slot)

        return results
