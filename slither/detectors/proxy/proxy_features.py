from abc import ABC

import sha3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.compilation_unit import SlitherCompilationUnit
from slither.core.declarations.structure import Structure
from slither.core.declarations.structure_contract import StructureContract
from slither.core.declarations.solidity_variables import SolidityVariable
from slither.core.variables.variable import Variable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.structure_variable import StructureVariable
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.literal import Literal
from slither.core.declarations.function_contract import FunctionContract
from slither.core.expressions.expression import Expression
from slither.core.expressions.expression_typed import ExpressionTyped
from slither.core.expressions.tuple_expression import TupleExpression
from slither.core.expressions.literal import Literal
from slither.core.expressions.call_expression import CallExpression
from slither.core.expressions.type_conversion import TypeConversion
from slither.core.expressions.assignment_operation import AssignmentOperation
from slither.core.expressions.binary_operation import BinaryOperation
from slither.core.expressions.member_access import MemberAccess
from slither.core.expressions.index_access import IndexAccess
from slither.core.solidity_types.mapping_type import MappingType, Type
from slither.core.solidity_types.user_defined_type import UserDefinedType
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.utils.function import get_function_id
import slither.analyses.data_dependency.data_dependency as dataDependency


class ProxyFeatureExtraction:
    """
    Wrapper class for extracting proxy features from a Contract object.
    Not a detector, but used exclusively by ProxyPatterns detector.
    """

    def __init__(self, contract: "Contract", compilation_unit: "SlitherCompilationUnit"):
        self.contract: Contract = contract
        self.compilation_unit: SlitherCompilationUnit = compilation_unit
        self._is_admin_only_proxy: Optional[bool] = None
        self._impl_address_variable: Optional["Variable"] = contract.delegate_variable
        self._impl_address_location: Optional["Contract"] = None

    ###################################################################################
    ###################################################################################
    # region general properties
    ###################################################################################
    ###################################################################################

    @property
    def is_proxy(self) -> bool:
        return self.contract.is_proxy

    @property
    def is_upgradeable_proxy(self) -> bool:
        return self.contract.is_upgradeable_proxy

    @property
    def is_upgradeable_proxy_confirmed(self) -> bool:
        return self.contract.is_upgradeable_proxy_confirmed

    @property
    def impl_address_variable(self) -> Optional["Variable"]:
        if self._impl_address_variable is None:
            self._impl_address_variable = self.contract.delegate_variable
        return self._impl_address_variable

    @property
    def impl_address_location(self) -> Optional["Contract"]:
        """
        Determine which contract the implementation address variable is declared in.

        :return: For state variables, just return the StateVariable.contract.
                 For local variables, return LocalVariable.function.contract
                  or self.contract if that contract is inherited by self.contract.
                 For structure variables, return StructureVariable.structure.contract.
        """
        if self._impl_address_location is None:
            if isinstance(self._impl_address_variable, StateVariable):
                self._impl_address_location = self._impl_address_variable.contract
            elif isinstance(self._impl_address_variable, LocalVariable):
                function = self._impl_address_variable.function
                if function is None:
                    self._impl_address_location = self.contract
                if isinstance(function, FunctionContract):
                    self._impl_address_location = function.contract
                    if self._impl_address_location in self.contract.inheritance:
                        self._impl_address_location = self.contract
            elif isinstance(self._impl_address_variable, StructureVariable):
                struct = self._impl_address_variable.structure
                if isinstance(struct, StructureContract):
                    self._impl_address_location = struct.contract
        return self._impl_address_location

    def is_impl_address_also_declared_in_logic(self) -> (int, Optional[Contract]):
        """
        If the implementation address variable is a StateVariable declared in the proxy,
        but the implementation setter is not declared in the proxy, then we need to determine
        if the implementation contract declares the same variable in the same slot.

        :return: The index indicating the position of the variable declaration, i.e. slot 0,
                 and the Contract in which the variable (and its setter) is also declared,
                 or else return -1 and None if this is not the case.
        """
        ret_index = -1
        ret_contract = None
        if isinstance(self._impl_address_variable, StateVariable):
            delegate = self._impl_address_variable
            setter = self.contract.proxy_implementation_setter
            if setter is not None and setter.contract != self.contract:
                ret_contract = setter.contract
                for idx, var in enumerate(self.contract.state_variables_ordered):
                    if var == delegate:
                        index = idx
                        break
                if index >= 0 and len(ret_contract.state_variables_ordered) >= index + 1:
                    var = ret_contract.state_variables_ordered[index]
                    if var is not None:
                        if var.name == delegate.name and var.type == delegate.type:
                            ret_index = index
        return ret_index, ret_contract

    def find_slot_in_setter_asm(self) -> Optional[str]:
        slot = None
        setter = self.contract.proxy_implementation_setter
        if setter is not None:
            for node in setter.all_nodes():
                if node.type == NodeType.ASSEMBLY and node.inline_asm is not None:
                    inline_asm = node.inline_asm
                    if "AST" in inline_asm and isinstance(inline_asm, Dict):
                        for statement in inline_asm["AST"]["statements"]:
                            if statement["nodeType"] == "YulExpressionStatement":
                                statement = statement["expression"]
                            if statement["nodeType"] == "YulVariableDeclaration":
                                statement = statement["value"]
                            if statement["nodeType"] == "YulFunctionCall":
                                if statement["functionName"]["name"] == "sstore":
                                    slot = statement["arguments"][0]
                    else:
                        asm_split = inline_asm.split("\n")
                        for asm in asm_split:
                            if "sstore" in asm:
                                params = asm.split("(")[1].strip(")").split(", ")
                                slot = params[0]
                    if slot is not None:
                        sv = self.contract.get_state_variable_from_name(slot)
                        if sv is None:
                            lv = node.function.get_local_variable_from_name(slot)
                            if lv is not None and lv.expression is not None and isinstance(lv.expression,
                                                                                           Identifier):
                                if isinstance(lv.expression.value, StateVariable):
                                    sv = lv.expression.value
                        if sv is not None and sv.expression is not None:
                            slot = str(sv.expression)
                        break
        return slot

    def all_mappings(self) -> Optional[List["MappingType"]]:
        """
        :return: List of all MappingType state variables found in the contract, or None if empty
        """
        mappings = []
        for v in self.contract.state_variables:
            if isinstance(v.type, MappingType):
                mappings.append(v.type)
        if len(mappings) == 0:
            return None
        return mappings

    def is_eternal_storage(self) -> bool:
        """
        Contracts using Eternal Storage must contain the following mappings:
            mapping(bytes32 => uint256) internal uintStorage;
            mapping(bytes32 => string) internal stringStorage;
            mapping(bytes32 => address) internal addressStorage;
            mapping(bytes32 => bytes) internal bytesStorage;
            mapping(bytes32 => bool) internal boolStorage;
            mapping(bytes32 => int256) internal intStorage;
        Note: the implementation address variable may be stored separately.

        :return: True if all of the above mappings are present, otherwise False.
        """
        mappings = self.all_mappings()
        types = ["uint256", "string", "address", "bytes", "bool", "int256"]
        if mappings is not None:
            maps_to = [str(m.type_to) for m in mappings]
            return all([t in maps_to for t in types])
        return False

    def find_impl_slot_from_sload(self) -> str:
        """
        Given the implementation address variable (which should be a LocalVariable
        if loaded from a storage slot), searches the CFG of the fallback function
        to extract the value of the storage slot it is loaded from (using sload).

        :return: A string, which should be the 32-byte storage slot location.
        """
        fallback = self.contract.fallback_function
        delegate = self.contract.delegate_variable
        slot = None
        """
        Use slither.analysis.data_dependency to expedite analysis if possible.
        """
        for sv in self.contract.state_variables:
            if dataDependency.is_dependent(delegate, sv, self.contract):
                print(f"{delegate} is dependent on {sv}")
                if str(sv.type) == "bytes32" and sv.is_constant:
                    return str(sv.expression)
        """
        Check if the slot was found during the initial execution of Contract.is_upgradeable_proxy().
        Comment out to ensure the rest of the code here works without it.
        """
        slot = self.contract.proxy_impl_storage_offset
        if slot is not None:
            if len(slot.name) == 66 and slot.name.startswith("0x"):
                return slot.name
            else:
                return str(slot.expression)
        if delegate.expression is not None:
            """
            Means the variable was assigned a value when it was first declared. 
            """
            exp = delegate.expression
            print(f"Expression for {delegate}: {exp}")
            if isinstance(exp, Identifier):
                v = self.unwrap_identifiers(exp)
                if v.expression is not None:
                    exp = v.expression
                else:
                    print(f"{v}.expression is None")
            if isinstance(exp, MemberAccess):
                print(f"MemberAccess: {exp.expression}")
                exp = exp.expression
            if isinstance(exp, CallExpression):
                print(f"Called: {exp.called}")
                # if str(exp.called).startswith("sload"):
                if len(exp.arguments) > 0:
                    arg = exp.arguments[0]
                    if len(str(arg)) == 66 and str(arg).startswith("0x"):
                        return str(arg)
                    elif isinstance(arg, Identifier):
                        v = self.unwrap_identifiers(arg)
                        if v.expression is not None:
                            exp = v.expression
                            if v.is_constant:
                                return str(v.expression)
                            elif str(v.type) == "bytes32":
                                return str(v)
                            elif isinstance(exp, Literal):
                                return str(exp)
                        else:
                            print(f"{v}.expression is None")
                    else:
                        print(f"CallExpression argument {arg} is not an Identifier")
        else:
            """
            Means the variable was declared before it was assigned a value.
            i.e., if the return value was given a name in the function signature.
            In this case we must search for where it was assigned a value. 
            """
            print(f"Expression for {delegate} is None")
            func = self.contract.proxy_implementation_getter
            if func is None:
                func = fallback
            for node in func.all_nodes():
                if node.type == NodeType.VARIABLE:
                    if node.variable_declaration != delegate:
                        continue
                    exp = node.variable_declaration.expression
                    print(f"find_impl_slot_from_sload: VARIABLE node: {exp}")
                    if exp is not None and isinstance(exp, Identifier):
                        slot = str(exp.value.expression)
                        return slot
                elif node.type == NodeType.EXPRESSION:
                    exp = node.expression
                    print(f"find_impl_slot_from_sload: EXPRESSION node: {exp}")
                    if isinstance(exp, AssignmentOperation):
                        left = exp.expression_left
                        right = exp.expression_right
                        if isinstance(left, Identifier) and left.value == delegate:
                            if isinstance(right, CallExpression) and str(right.called) == "sload":
                                slot = right.arguments[0]
                elif node.type == NodeType.ASSEMBLY:
                    print(f"find_impl_slot_from_sload: ASSEMBLY node: {node.inline_asm}")
                    if "AST" in node.inline_asm and isinstance(node.inline_asm, Dict):
                        for statement in node.inline_asm["AST"]["statements"]:
                            if statement["nodeType"] == "YulExpressionStatement":
                                statement = statement["expression"]
                            if statement["nodeType"] == "YulVariableDeclaration":
                                if statement["variables"][0]["name"] != delegate.name:
                                    continue
                                statement = statement["value"]
                            if statement["nodeType"] == "YulAssignment":
                                if statement["variableNames"][0]["name"] != delegate.name:
                                    continue
                                statement = statement["value"]
                            if statement["nodeType"] == "YulFunctionCall":
                                if statement["functionName"]["name"] == "sload":
                                    slot = statement["arguments"][0]["name"]
                    else:
                        asm_split = node.inline_asm.split("\n")
                        for asm in asm_split:
                            # print(f"checking assembly line: {asm}")
                            if "sload" in asm and str(delegate) in asm:
                                slot = asm.split("(")[1].strip(")")
                if slot is not None and len(str(slot)) != 66:
                    sv = self.contract.get_state_variable_from_name(slot)
                    if sv is None:
                        lv = node.function.get_local_variable_from_name(slot)
                        if lv is not None and lv.expression is not None:
                            exp = lv.expression
                            while isinstance(exp, Identifier) and isinstance(exp.value, LocalVariable):
                                exp = exp.value.expression
                            if isinstance(exp, Identifier) and isinstance(exp.value, StateVariable):
                                sv = exp.value
                    if sv is not None and sv.expression is not None and (sv.is_constant or str(sv.type) == "bytes32"):
                        slot = str(sv.expression)
                        break
                    elif sv is not None and sv.expression is None:
                        print(f"{sv} is missing an expression")
                    else:
                        print(f"Could not find StateVariable from {slot}")
                elif slot is not None:
                    break
        return slot

    def proxy_only_contains_fallback(self) -> bool:
        """
        Determine whether the proxy contract contains any external/public functions
        besides the fallback, not including the constructor or receive function.

        :return: False if any other external/public function is found, or if the
                 fallback function is missing, otherwise True
        """
        is_true = False
        for function in self.contract.functions:
            if function.is_fallback:
                print(f"Found {function.name}")
                is_true = True
            elif function.visibility in ["external", "public"]:
                print(f"Found {function.visibility} function: {function.name}")
                if function.is_receive or function.is_constructor:
                    continue
                return False
        return is_true

    def external_functions_require_specific_sender(self) -> (bool, str):
        """
        Determine whether all external functions (besides fallback() and receive())
        are only callable by a specific address, and whether the fallback and receive
        functions are only callable by addresses other than the same specific address,
        i.e., whether this proxy uses the Transparent Proxy pattern.

        :return: True if the above conditions are met, otherwise False
        """
        admin_exp = None
        checks = []
        has_external_functions = False
        for function in self.contract.functions:
            if not function.is_fallback and not function.is_constructor and not function.is_receive:
                """
                Check for 'msg.sender ==' comparison in all external/public functions 
                besides fallback, receive and constructor
                """
                comparator = "=="
            elif not function.is_constructor:
                """
                Check for 'msg.sender !=' comparison in fallback and receive functions
                """
                comparator = "!="
            else:
                """
                Skip the constructor
                """
                continue
            if function.visibility in ["external", "public"]:
                check = False
                has_external_functions = True
                print(f"Checking {function.visibility} function {function}")
                for exp in function.all_expressions():
                    """
                    function.all_expressions() is a recursive getter which includes
                    expressions from all functions/modifiers called in given function.
                    """
                    if ('msg.sender ' + comparator) in str(exp):
                        print(f"Found 'msg.sender {comparator}' in expression: {exp}")
                    if "require" in str(exp) or "assert" in str(exp):
                        """
                        'require' and 'assert' are Solidity functions which always
                        take a boolean expression as the first argument.
                        """
                        if isinstance(exp, CallExpression) and len(exp.arguments) > 0:
                            exp = exp.arguments[0]
                    if isinstance(exp, Identifier):
                        value = self.unwrap_identifiers(exp)
                        if value is None:
                            continue
                        exp = value.expression
                    if isinstance(exp, BinaryOperation) and str(exp.type) == comparator:
                        """
                        For this method to return true, we must find a comparison expression,
                        i.e., a BinaryOperation, with 'msg.sender' on one side and the
                        admin_exp on the other side, where admin_exp must be the same in all.
                        """
                        if str(exp.expression_left) == "msg.sender":
                            exp = exp.expression_right
                        elif str(exp.expression_right) == "msg.sender":
                            exp = exp.expression_left
                        else:
                            continue
                        if admin_exp is None:
                            admin_exp = str(exp)
                            check = True
                            break
                        elif str(exp) == admin_exp:
                            check = True
                            break
                        print(admin_exp)
                checks.append(check)
        return (all(checks) and has_external_functions), admin_exp

    def impl_address_from_contract_call(self) -> (bool, Optional[Expression], Optional[Type]):
        """
        Determine whether the proxy contract retrieves the address of the
        implementation contract by calling a function in a third contract,
        i.e. from a Beacon or Registry contract.

        Note: Because the initial execution of contract.is_upgradeable_proxy()
              performs cross-contract analysis to trace this contract call,
              if successful, impl_address_variable will be a StateVariable
              declared in said third contract. But what we really want is a
              LocalVariable which gets its value from a CallExpression, which
              is what we'd have if the initial cross-contract analysis failed.

        :return: True if cross-contract call was found, as well as the actual
                 CallExpression and the Type of the contract being called.
                 Otherwise, returns (False, None, None).
        """
        delegate = self.impl_address_variable
        e = delegate.expression
        print(f"impl_address_from_contract_call: {e}")
        ret_exp = None
        c_type = None
        is_cross_contract = False
        if isinstance(delegate, StateVariable) and delegate.contract != self.contract:
            print(f"impl_address_from_contract_call: StateVariable {delegate}")
            """
            This indicates that cross-contract analysis during the initial execution of
            contract.is_upgradeable_proxy() was able to identify the variable which is
            returned by the cross-contract call. In this case, in order to return the
            CallExpression which returned this value, we need to re-find it first.
            """
            getter = self.contract.proxy_implementation_getter
            print(f"impl_address_from_contract_call: getter is {getter}")
            if getter is None and delegate.visibility in ["public", "external"]:
                getter = delegate
            for node in self.contract.fallback_function.all_nodes():
                exp = node.expression
                if isinstance(exp, AssignmentOperation):
                    exp = exp.expression_right
                    """Fall through to below"""
                if isinstance(exp, CallExpression):
                    print(f"impl_address_from_contract_call: CallExpression {exp}")
                    called = exp.called
                    if isinstance(called, Identifier):
                        f = called.value
                        if isinstance(f, FunctionContract) and f == getter:
                            e = exp
                            print(f"found CallExpression calling getter in another contract: {e}")
                            break
                    elif isinstance(called, MemberAccess) and called.member_name == getter.name:
                        e = exp
                        print(f"found MemberAccess calling getter in another contract: {e}")
                        break
        while isinstance(e, CallExpression):
            """
            Unwrap the (possibly nested) function calls until a MemberAccess is found.
            An example of why this is necessary (from tests/proxies/APMRegistry.sol):
                function () payable public {
                    address target = getCode();
                    require(target != 0); // if app code hasn't been set yet, don't call
                    delegatedFwd(target, msg.data);
                }
                function getCode() public view returns (address) {
                    return getAppBase(appId);
                }
                function getAppBase(bytes32 _appId) internal view returns (address) {
                    return kernel.getApp(keccak256(APP_BASES_NAMESPACE, _appId));
                }
            """
            called = e.called
            print(f"called: {called}")
            if isinstance(called, Identifier):
                f = called.value
                if isinstance(f, FunctionContract):
                    e = f.return_node().expression
                    print(f"{called} returns {e}")
                else:
                    e = f.expression
            elif isinstance(called, MemberAccess):
                ret_exp = e
                e = called
                print(f"found MemberAccess: {e}")
            else:
                print(f"{called} is not Identifier or MemberAccess")
                break
        if isinstance(e, MemberAccess):
            e = e.expression
            if isinstance(e, CallExpression) and isinstance(e.called, Identifier):
                f = e.called.value
                if isinstance(f, FunctionContract):
                    e = f.return_node().expression
            if isinstance(e, TypeConversion) or isinstance(e, Identifier):
                c_type = e.type
                if isinstance(e, Identifier):
                    print(f"Identifier: {e}")
                    if isinstance(e.value, Contract):
                        print(f"value is Contract: {e.value}")
                        c_type = UserDefinedType(e.value)
                    else:
                        c_type = e.value.type
                        if isinstance(e.value, StateVariable):
                            print(f"value is StateVariable: {e.value}\nType: {c_type}")
                elif isinstance(e, TypeConversion):
                    print(f"TypeConversion: {e}")
                    exp = e.expression
                    if isinstance(exp, Literal):
                        ret_exp = exp
                if isinstance(c_type, UserDefinedType) and isinstance(c_type.type,
                                                                      Contract) and c_type.type != self:
                    is_cross_contract = True
                    if c_type.type.is_interface or (getter is not None and c_type.type != getter.contract):
                        for c in self.compilation_unit.contracts:
                            if c_type.type in c.inheritance:
                                c_type = UserDefinedType(c)
                elif str(c_type) == "address":
                    is_cross_contract = True
                    getter = self.contract.proxy_implementation_getter
                    if getter is not None and getter.contract != self.contract:
                        c_type = UserDefinedType(getter.contract)
        return is_cross_contract, ret_exp, c_type

    def find_registry_address_source(self, call: CallExpression) -> Optional[Variable]:
        """
        Determine the source of the address of the third contract from which the proxy retrieves
        its implementation address, i.e., where the Registry/Beacon address is stored.

        :param call: The CallExpression returned by impl_address_from_contract_call()
        """
        print(f"find_registry_address_source: {call}")
        exp = call.called
        value = None
        if isinstance(exp, MemberAccess):
            print(f"MemberAccess: {exp}")
            exp = exp.expression
            """fall-through to below"""
        if isinstance(exp, TypeConversion):
            print(f"TypeConversion: {exp}")
            exp = exp.expression
            """fall-through to below"""
        if isinstance(exp, CallExpression):
            print(f"CallExpression: {exp}")
            exp = exp.called
            """fall-through to below"""
        if isinstance(exp, Identifier):
            print(f"Identifier: {exp}")
            value = exp.value
            while isinstance(value, LocalVariable):
                print(f"LocalVariable: {value}")
                exp = value.expression
                if exp is not None:
                    if isinstance(exp, CallExpression):
                        """recursive call with new expression"""
                        return self.find_registry_address_source(exp)
                    elif isinstance(exp, Identifier):
                        value = exp.value
                        """fall-through to below, or repeat for another LocalVariable"""
                else:
                    break
            if isinstance(value, FunctionContract):
                func = value
                if len(func.returns) > 0:
                    value = func.returns[0]
                    ret_node = func.return_node()
                    if ret_node is not None and (value.name is None or value.name == ""):
                        """
                        If return value is unnamed, check return node expression
                        """
                        exp = ret_node.expression
                        if exp is not None:
                            if isinstance(exp, CallExpression):
                                """recursive call with new expression"""
                                return self.find_registry_address_source(exp)
                            if isinstance(exp, Identifier):
                                value = exp.value
                    elif value.name is not None and value.name != "":
                        """
                        If return value is named, find where it is assigned a value
                        """
                        for node in func.all_nodes():
                            if node.type == NodeType.EXPRESSION:
                                exp = node.expression
                                print(f"EXPRESSION node: {exp}")
                                if isinstance(exp, AssignmentOperation):
                                    left = exp.expression_left
                                    right = exp.expression_right
                                    if isinstance(left, Identifier) and left.value == value:
                                        if isinstance(right, CallExpression):
                                            print(f"Called: {right.called}")
                                            if str(right.called).startswith("sload"):
                                                exp = right.arguments[0]
                                                if isinstance(exp, Identifier):
                                                    value = exp.value
                                                if isinstance(value, LocalVariable):
                                                    exp = value.expression
                                                    if isinstance(exp, Identifier):
                                                        value = exp.value
                                            else:
                                                return self.find_registry_address_source(right)
                                        if isinstance(right, Identifier):
                                            value = right.value
                                            break
                            elif node.type == NodeType.ASSEMBLY:
                                if "AST" not in node.inline_asm and not isinstance(node.inline_asm, Dict):
                                    asm_split = node.inline_asm.split("\n")
                                    for asm in asm_split:
                                        # print(f"checking assembly line: {asm}")
                                        if "sload" in asm and value.name in asm:
                                            slot = asm.split("(")[1].strip(")")
                                            value = self.contract.get_state_variable_from_name(slot)
                                            if value is None:
                                                lv = node.function.get_local_variable_from_name(slot)
                                                if lv is not None and lv.expression is not None:
                                                    exp = lv.expression
                                                    if isinstance(exp, Identifier) and isinstance(exp.value,
                                                                                                  StateVariable):
                                                        value = exp.value
        return value

    def is_mapping_from_msg_sig(self, mapping: Variable) -> bool:
        """
        Determine whether the given variable is a mapping with function signatures as keys

        :param mapping: Should be a Variable with mapping.type == MappingType
        :return: True if a matching IndexAccess expression is found using msg.sig as the key, otherwise False
        """
        ret = False
        m_type = mapping.type
        if isinstance(m_type, MappingType):
            if str(m_type.type_from) != "bytes4":
                return False
            for node in self.contract.fallback_function.all_nodes():
                if node.type == NodeType.EXPRESSION or node.type == NodeType.VARIABLE:
                    if node.expression is None:
                        continue
                    exp = node.expression
                    if isinstance(exp, AssignmentOperation):
                        exp = exp.expression_right
                    if isinstance(exp, MemberAccess):
                        exp = exp.expression
                    if isinstance(exp, IndexAccess):
                        if mapping.name in str(exp.expression_left) and str(exp.expression_right) == "msg.sig":
                            ret = True
        return ret

    def find_diamond_loupe_functions(self) -> Optional[List[Tuple[str, "Contract"]]]:
        """
        For EIP-2535 Diamonds, determine if all four Loupe functions are
        included in any of the "Facet" contracts in the compilation unit.
        These functions are required to be compliant with the standard, and
        it is not sufficient to only include the interface w/o implementations.

        :return: List of (function signature, Contract) pairs indicating
                 which contract contains each of the Loupe functions.
        """
        loupe_facets = []
        loupe_sigs = [
            "facets() returns(IDiamondLoupe.Facet[])",
            "facetAddresses() returns(address[])",
            "facetAddress(bytes4) returns(address)",
            "facetFunctionSelectors(address) returns(bytes4[])"
        ]
        for c in self.compilation_unit.contracts:
            if c == self.contract or c.is_interface:
                continue
            print(f"Looking for Loupe functions in {c}")
            for f in c.functions:
                print(f.signature_str)
                if f.signature_str in loupe_sigs:
                    loupe_sigs.remove(f.signature_str)
                    loupe_facets.append((f.signature_str, c))
        return loupe_facets

    def unwrap_identifiers(
            self,
            exp: Expression
    ) -> Optional[Variable]:
        ret_val = None
        while isinstance(exp, Identifier):
            val = exp.value
            if isinstance(val, SolidityVariable):
                """
                The SolidityVariable class does not inherit Variable, 
                so we cannot immediately set exp = val.expression.
                If the name ends with _slot or _offset, it indicates
                a property of the StateVariable with the same name,
                minus the suffix. The _ here is like dot notation.
                (i.e. delegate_slot = the slot where delegate is stored)
                """
                if val.name.endswith("_slot") or val.name.endswith("_offset"):
                    val = self.impl_address_location.get_state_variable_from_name(val.state_variable)
                else:
                    return ret_val
            ret_val = val
            exp = ret_val.expression
        return ret_val

    # endregion
    ###################################################################################
    ###################################################################################
    # region Static methods
    ###################################################################################
    ###################################################################################

    @staticmethod
    def find_slot_string_from_assert(
            proxy: Contract,
            slot: StateVariable
    ):
        slot_string = None
        assert_exp = None
        minus = 0
        if proxy.constructor is not None:
            for exp in proxy.constructor.all_expressions():
                if isinstance(exp, CallExpression) and str(exp.called) == "assert(bool)" and slot.name in str(exp):
                    print(f"Found assert statement in constructor:\n{str(exp)}")
                    assert_exp = exp
                    arg = exp.arguments[0]
                    if isinstance(arg, BinaryOperation) and str(arg.type) == "==" and arg.expression_left.value == slot:
                        e = arg.expression_right
                        print("BinaryOperation ==")
                        if isinstance(e, TypeConversion) and str(e.type) == "bytes32":
                            print(f"TypeConversion bytes32: {str(e)}")
                            e = e.expression
                        if isinstance(e, BinaryOperation) and str(e.type) == "-":
                            print(f"BinaryOperation -: {str(e)}")
                            if isinstance(e.expression_right, Literal):
                                print(f"Minus: {str(e.expression_right.value)}")
                                minus = int(e.expression_right.value)
                                e = e.expression_left
                        if isinstance(e, TypeConversion) and str(e.type) == "uint256":
                            print(f"TypeConversion uint256: {str(e)}")
                            e = e.expression
                        if isinstance(e, CallExpression) and "keccak256(" in str(e.called):
                            print(f"CallExpression keccak256: {str(e)}")
                            arg = e.arguments[0]
                            if isinstance(arg, Literal):
                                if str(arg.type) == "string":
                                    slot_string = arg.value
                                    break
        return slot_string, assert_exp, minus

    @staticmethod
    def find_mapping_in_var_exp(
            delegate: Variable,
            proxy: Contract
    ) -> (Optional["Variable"], Optional["IndexAccess"]):
        mapping = None
        exp = None
        e = delegate.expression
        if e is not None:
            print(f"{delegate} expression is {e}")
            while isinstance(e, TypeConversion) or isinstance(e, MemberAccess):
                e = e.expression
            if isinstance(e, IndexAccess):
                exp = e
                left = e.expression_left
                if isinstance(left, MemberAccess):
                    e = left.expression
                    member = left.member_name
                    if isinstance(e, Identifier):
                        v = e.value
                        if isinstance(v.type, UserDefinedType) and isinstance(v.type.type, Structure):
                            if isinstance(v.type.type.elems[member].type, MappingType):
                                mapping = v.type.type.elems[member]
                elif isinstance(left, Identifier):
                    v = left.value
                    if isinstance(v.type, MappingType):
                        mapping = v
        elif isinstance(delegate.type, MappingType):
            mapping = delegate
            for e in proxy.fallback_function.variables_read_as_expression:
                if isinstance(e, IndexAccess) and isinstance(e.expression_left, Identifier):
                    if e.expression_left.value == mapping:
                        exp = e
                        break
        return mapping, exp

    # endregion
