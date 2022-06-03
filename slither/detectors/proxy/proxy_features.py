from abc import ABC

import sha3
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union
from slither.core.cfg.node import NodeType
from slither.core.declarations.contract import Contract
from slither.core.compilation_unit import SlitherCompilationUnit
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
        self._proxy_impl_setter: Optional["Function"] = None
        self._proxy_impl_getter: Optional["Function"] = None
        self._proxy_impl_slot: Optional["Variable"] = None
        self._proxy_storage_slots: Optional[List["Variable"]] = None
        self._proxy_storage_contract: Optional["Contract"] = None
        self._proxy_registry_contract: Optional["Contract"] = None
        self._proxy_admin_contract: Optional["Contract"] = None
        self._has_multiple_implementations: Optional[bool] = None
        self._is_storage_inherited: Optional[bool] = None
        self._is_storage_eternal: Optional[bool] = None
        self._is_storage_unstructured: Optional[bool] = None

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

    def find_slot_in_setter_asm(self) -> Optional[str]:
        slot = None
        delegate = self._impl_address_variable
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
                                    if statement["arguments"][1] == delegate.name:
                                        slot = statement["arguments"][0]
                    else:
                        asm_split = inline_asm.split("\n")
                        for asm in asm_split:
                            if "sstore" in asm:
                                params = asm.split("(")[1].strip(")").split(", ")
                                slot = params[0]
        return slot

    def all_mappings(self) -> Optional[List["MappingType"]]:
        mappings = []
        for v in self.impl_address_location.state_variables:
            if isinstance(v.type, MappingType):
                mappings.append(v.type)
        if len(mappings) == 0:
            return None
        return mappings

    def is_eternal_storage(self) -> bool:
        mappings = self.all_mappings()
        types = ["uint256", "string", "address", "bytes", "bool", "int256"]
        types2 = types
        if mappings is not None:
            for t in types:
                for m in mappings:
                    if str(m.type_to) == t and (str(m.type_from) == "string" or str(m.type_from) == "bytes32"):
                        types2.remove(t)
        return len(types2) == 0

    def find_impl_slot_from_sload(self) -> str:
        fallback = self.contract.fallback_function
        delegate = self.contract.delegate_variable
        slot = self.contract.proxy_impl_storage_offset
        if slot is not None:
            if len(slot.name) == 66 and slot.name.startswith("0x"):
                return slot.name
            else:
                return str(slot.expression)
        elif delegate.expression is not None:
            exp = delegate.expression
            print(f"Expression for {delegate}: {exp}")
            if isinstance(exp, CallExpression):
                print(f"Called: {exp.called}")
                if str(exp.called).startswith("sload"):
                    # params = exp.split("(")[1].strip(")")
                    arg = exp.arguments[0]
                    if len(str(arg)) == 66 and str(arg).startswith("0x"):
                        return str(arg)
                    elif isinstance(arg, Identifier):
                        v = arg.value
                        if v.expression is not None:
                            exp = v.expression
                            if isinstance(exp, Identifier) and exp.value.is_constant:
                                return str(exp.value.expression)
        else:
            for node in fallback.all_nodes():
                if node.type == NodeType.VARIABLE:
                    exp = node.variable_declaration.expression
                    if exp is not None and isinstance(exp, Identifier):
                        slot = str(exp.value.expression)
                        return slot
                elif node.type == NodeType.ASSEMBLY:
                    slot = None
                    if "AST" in node.inline_asm and isinstance(node.inline_asm, Dict):
                        for statement in node.inline_asm["AST"]["statements"]:
                            if statement["nodeType"] == "YulExpressionStatement":
                                statement = statement["expression"]
                            if statement["nodeType"] == "YulVariableDeclaration":
                                statement = statement["value"]
                            if statement["nodeType"] == "YulFunctionCall":
                                if statement["functionName"]["name"] == "sload":
                                    if statement["arguments"][1] == delegate.name:
                                        slot = statement["arguments"][0]
                    else:
                        asm_split = node.inline_asm.split("\n")
                        for asm in asm_split:
                            if "sload" in asm:
                                params = asm.split("(")[1].strip(")")
                                slot = params[0]
                    return slot

    def proxy_onlyHave_constructor_fallback(self) -> bool:
        i=0
        for function in self.contract.functions_declared:
            if function.is_constructor or function.is_fallback:
                i += 1
            elif function.visibility in ["external", "public"]:
                return False
        return i == 2

    def external_function_specific_call(self) -> bool:
        for function in self.contract.functions_declared:
            if (not function.is_fallback) and (not function.is_constructor) and\
                    (function.visibility in ["external", "public"]):
                for node in function.all_nodes():
                    if node.type == NodeType.EXPRESSION:
                        exp = node.expression
                        if 'msg.sender' in str(exp):
                            """
                            do something
                            """

    def implementation_address_from_contractcall(self) -> bool:
        call = self.contract.delegate_variable.expression
        if isinstance(call, CallExpression):
            call = call.called
            if isinstance(call, MemberAccess):
                e = call.expression
                if isinstance(e, CallExpression) and isinstance(e.called, Identifier):
                    f = e.called.value
                    if isinstance(f, FunctionContract):
                        e = f.return_node().expression
                if isinstance(e, TypeConversion) or isinstance(e, Identifier):
                    ctype = e.type
                    if isinstance(e, Identifier):
                        if isinstance(e.value, Contract):
                            ctype = UserDefinedType(e.value)
                        else:
                            ctype = e.value.type
                    if isinstance(ctype, UserDefinedType) and isinstance(ctype.type,
                                                                         Contract) and ctype.type != self:
                        return True
        return False

    def is_mapping_from_msg_sig(self, mapping: Variable) -> bool:
        ret = False
        if isinstance(mapping.type, MappingType):
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
