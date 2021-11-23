""""
    Contract module
"""
import logging
from pathlib import Path
from typing import Optional, List, Dict, Callable, Tuple, TYPE_CHECKING, Union

from crytic_compile.platform import Type as PlatformType

import slither.core.declarations.contract
from slither.core.cfg.scope import Scope
from slither.core.solidity_types.type import Type
from slither.core.source_mapping.source_mapping import SourceMapping

from slither.core.declarations.function import Function, FunctionType
from slither.utils.erc import (
    ERC20_signatures,
    ERC165_signatures,
    ERC223_signatures,
    ERC721_signatures,
    ERC1820_signatures,
    ERC777_signatures,
    ERC1155_signatures,
)
from slither.utils.tests_pattern import is_test_contract

# pylint: disable=too-many-lines,too-many-instance-attributes,import-outside-toplevel,too-many-nested-blocks
if TYPE_CHECKING:
    from slither.utils.type_helpers import LibraryCallType, HighLevelCallType, InternalCallType
    from slither.core.declarations import (
        Enum,
        Event,
        Modifier,
        EnumContract,
        StructureContract,
        FunctionContract,
    )
    from slither.slithir.variables.variable import SlithIRVariable
    from slither.core.variables.variable import Variable
    from slither.core.variables.state_variable import StateVariable
    from slither.core.compilation_unit import SlitherCompilationUnit

LOGGER = logging.getLogger("Contract")


class Contract(SourceMapping):  # pylint: disable=too-many-public-methods
    """
    Contract class
    """

    def __init__(self, compilation_unit: "SlitherCompilationUnit"):
        super().__init__()

        self._name: Optional[str] = None
        self._id: Optional[int] = None
        self._inheritance: List["Contract"] = []  # all contract inherited, c3 linearization
        self._immediate_inheritance: List["Contract"] = []  # immediate inheritance

        # Constructors called on contract's definition
        # contract B is A(1) { ..
        self._explicit_base_constructor_calls: List["Contract"] = []

        self._enums: Dict[str, "EnumContract"] = {}
        self._structures: Dict[str, "StructureContract"] = {}
        self._events: Dict[str, "Event"] = {}
        self._variables: Dict[str, "StateVariable"] = {}
        self._variables_ordered: List["StateVariable"] = []
        self._modifiers: Dict[str, "Modifier"] = {}
        self._functions: Dict[str, "FunctionContract"] = {}
        self._linearizedBaseContracts: List[int] = []

        # The only str is "*"
        self._using_for: Dict[Union[str, Type], List[str]] = {}
        self._kind: Optional[str] = None
        self._is_interface: bool = False

        self._signatures: Optional[List[str]] = None
        self._signatures_declared: Optional[List[str]] = None

        self._is_upgradeable: Optional[bool] = None
        self._is_upgradeable_proxy: Optional[bool] = None
        self._fallback_function: Optional["FunctionContract"] = None
        self._is_proxy: Optional[bool] = None
        self._delegates_to: Optional["Variable"] = None
        self._proxy_impl_setter: Optional["Function"] = None
        self._proxy_impl_getter: Optional["Function"] = None
        self._proxy_impl_slot: Optional["Variable"] = None

        self.is_top_level = False  # heavily used, so no @property

        self._initial_state_variables: List["StateVariable"] = []  # ssa

        self._is_incorrectly_parsed: bool = False

        self._available_functions_as_dict: Optional[Dict[str, "Function"]] = None
        self._all_functions_called: Optional[List["InternalCallType"]] = None

        self.compilation_unit: "SlitherCompilationUnit" = compilation_unit

    ###################################################################################
    ###################################################################################
    # region General's properties
    ###################################################################################
    ###################################################################################

    @property
    def name(self) -> str:
        """str: Name of the contract."""
        assert self._name
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def id(self) -> int:
        """Unique id."""
        assert self._id
        return self._id

    @id.setter
    def id(self, new_id):
        """Unique id."""
        self._id = new_id

    @property
    def contract_kind(self) -> Optional[str]:
        """
        contract_kind can be None if the legacy ast format is used
        :return:
        """
        return self._kind

    @contract_kind.setter
    def contract_kind(self, kind):
        self._kind = kind

    @property
    def is_interface(self) -> bool:
        return self._is_interface

    @is_interface.setter
    def is_interface(self, is_interface: bool):
        self._is_interface = is_interface

    # endregion
    ###################################################################################
    ###################################################################################
    # region Structures
    ###################################################################################
    ###################################################################################

    @property
    def structures(self) -> List["StructureContract"]:
        """
        list(Structure): List of the structures
        """
        return list(self._structures.values())

    @property
    def structures_inherited(self) -> List["StructureContract"]:
        """
        list(Structure): List of the inherited structures
        """
        return [s for s in self.structures if s.contract != self]

    @property
    def structures_declared(self) -> List["StructureContract"]:
        """
        list(Structues): List of the structures declared within the contract (not inherited)
        """
        return [s for s in self.structures if s.contract == self]

    @property
    def structures_as_dict(self) -> Dict[str, "StructureContract"]:
        return self._structures

    # endregion
    ###################################################################################
    ###################################################################################
    # region Enums
    ###################################################################################
    ###################################################################################

    @property
    def enums(self) -> List["EnumContract"]:
        return list(self._enums.values())

    @property
    def enums_inherited(self) -> List["EnumContract"]:
        """
        list(Enum): List of the inherited enums
        """
        return [e for e in self.enums if e.contract != self]

    @property
    def enums_declared(self) -> List["EnumContract"]:
        """
        list(Enum): List of the enums declared within the contract (not inherited)
        """
        return [e for e in self.enums if e.contract == self]

    @property
    def enums_as_dict(self) -> Dict[str, "EnumContract"]:
        return self._enums

    # endregion
    ###################################################################################
    ###################################################################################
    # region Events
    ###################################################################################
    ###################################################################################

    @property
    def events(self) -> List["Event"]:
        """
        list(Event): List of the events
        """
        return list(self._events.values())

    @property
    def events_inherited(self) -> List["Event"]:
        """
        list(Event): List of the inherited events
        """
        return [e for e in self.events if e.contract != self]

    @property
    def events_declared(self) -> List["Event"]:
        """
        list(Event): List of the events declared within the contract (not inherited)
        """
        return [e for e in self.events if e.contract == self]

    @property
    def events_as_dict(self) -> Dict[str, "Event"]:
        return self._events

    # endregion
    ###################################################################################
    ###################################################################################
    # region Using for
    ###################################################################################
    ###################################################################################

    @property
    def using_for(self) -> Dict[Union[str, Type], List[str]]:
        return self._using_for

    # endregion
    ###################################################################################
    ###################################################################################
    # region Variables
    ###################################################################################
    ###################################################################################

    @property
    def variables(self) -> List["StateVariable"]:
        """
        list(StateVariable): List of the state variables. Alias to self.state_variables
        """
        return list(self.state_variables)

    @property
    def variables_as_dict(self) -> Dict[str, "StateVariable"]:
        return self._variables

    @property
    def state_variables(self) -> List["StateVariable"]:
        """
        list(StateVariable): List of the state variables.
        """
        return list(self._variables.values())

    @property
    def state_variables_ordered(self) -> List["StateVariable"]:
        """
        list(StateVariable): List of the state variables by order of declaration.
        """
        return list(self._variables_ordered)

    def add_variables_ordered(self, new_vars: List["StateVariable"]):
        self._variables_ordered += new_vars

    @property
    def state_variables_inherited(self) -> List["StateVariable"]:
        """
        list(StateVariable): List of the inherited state variables
        """
        return [s for s in self.state_variables if s.contract != self]

    @property
    def state_variables_declared(self) -> List["StateVariable"]:
        """
        list(StateVariable): List of the state variables declared within the contract (not inherited)
        """
        return [s for s in self.state_variables if s.contract == self]

    @property
    def slithir_variables(self) -> List["SlithIRVariable"]:
        """
        List all of the slithir variables (non SSA)
        """
        slithir_variabless = [f.slithir_variables for f in self.functions + self.modifiers]  # type: ignore
        slithir_variables = [item for sublist in slithir_variabless for item in sublist]
        return list(set(slithir_variables))

    # endregion
    ###################################################################################
    ###################################################################################
    # region Constructors
    ###################################################################################
    ###################################################################################

    @property
    def constructor(self) -> Optional["Function"]:
        """
        Return the contract's immediate constructor.
        If there is no immediate constructor, returns the first constructor
        executed, following the c3 linearization
        Return None if there is no constructor.
        """
        cst = self.constructors_declared
        if cst:
            return cst
        for inherited_contract in self.inheritance:
            cst = inherited_contract.constructors_declared
            if cst:
                return cst
        return None

    @property
    def constructors_declared(self) -> Optional["Function"]:
        return next(
            (
                func
                for func in self.functions
                if func.is_constructor and func.contract_declarer == self
            ),
            None,
        )

    @property
    def constructors(self) -> List["Function"]:
        """
        Return the list of constructors (including inherited)
        """
        return [func for func in self.functions if func.is_constructor]

    @property
    def explicit_base_constructor_calls(self) -> List["Function"]:
        """
        list(Function): List of the base constructors called explicitly by this contract definition.

                        Base constructors called by any constructor definition will not be included.
                        Base constructors implicitly called by the contract definition (without
                        parenthesis) will not be included.

                        On "contract B is A(){..}" it returns the constructor of A
        """
        return [c.constructor for c in self._explicit_base_constructor_calls if c.constructor]

    # endregion
    ###################################################################################
    ###################################################################################
    # region Functions and Modifiers
    ###################################################################################
    ###################################################################################

    @property
    def functions_signatures(self) -> List[str]:
        """
        Return the signatures of all the public/eterxnal functions/state variables
        :return: list(string) the signatures of all the functions that can be called
        """
        if self._signatures is None:
            sigs = [
                v.full_name for v in self.state_variables if v.visibility in ["public", "external"]
            ]

            sigs += {f.full_name for f in self.functions if f.visibility in ["public", "external"]}
            self._signatures = list(set(sigs))
        return self._signatures

    @property
    def functions_signatures_declared(self) -> List[str]:
        """
        Return the signatures of the public/eterxnal functions/state variables that are declared by this contract
        :return: list(string) the signatures of all the functions that can be called and are declared by this contract
        """
        if self._signatures_declared is None:
            sigs = [
                v.full_name
                for v in self.state_variables_declared
                if v.visibility in ["public", "external"]
            ]

            sigs += {
                f.full_name
                for f in self.functions_declared
                if f.visibility in ["public", "external"]
            }
            self._signatures_declared = list(set(sigs))
        return self._signatures_declared

    @property
    def functions(self) -> List["FunctionContract"]:
        """
        list(Function): List of the functions
        """
        return list(self._functions.values())

    def available_functions_as_dict(self) -> Dict[str, "FunctionContract"]:
        if self._available_functions_as_dict is None:
            self._available_functions_as_dict = {
                f.full_name: f for f in self._functions.values() if not f.is_shadowed
            }
        return self._available_functions_as_dict

    def add_function(self, func: "FunctionContract"):
        self._functions[func.canonical_name] = func

    def set_functions(self, functions: Dict[str, "FunctionContract"]):
        """
        Set the functions

        :param functions:  dict full_name -> function
        :return:
        """
        self._functions = functions

    @property
    def functions_inherited(self) -> List["FunctionContract"]:
        """
        list(Function): List of the inherited functions
        """
        return [f for f in self.functions if f.contract_declarer != self]

    @property
    def functions_declared(self) -> List["FunctionContract"]:
        """
        list(Function): List of the functions defined within the contract (not inherited)
        """
        return [f for f in self.functions if f.contract_declarer == self]

    @property
    def functions_entry_points(self) -> List["FunctionContract"]:
        """
        list(Functions): List of public and external functions
        """
        return [
            f
            for f in self.functions
            if f.visibility in ["public", "external"] and not f.is_shadowed or f.is_fallback
        ]

    @property
    def fallback_function(self) -> Optional["FunctionContract"]:
        """
        optional(FunctionContract): The fallback function
        """
        if self._fallback_function is None:
            for f in self.functions:
                if f.is_fallback:
                    self._fallback_function = f
                    break
        return self._fallback_function

    @property
    def modifiers(self) -> List["Modifier"]:
        """
        list(Modifier): List of the modifiers
        """
        return list(self._modifiers.values())

    def available_modifiers_as_dict(self) -> Dict[str, "Modifier"]:
        return {m.full_name: m for m in self._modifiers.values() if not m.is_shadowed}

    def set_modifiers(self, modifiers: Dict[str, "Modifier"]):
        """
        Set the modifiers

        :param modifiers:  dict full_name -> modifier
        :return:
        """
        self._modifiers = modifiers

    @property
    def modifiers_inherited(self) -> List["Modifier"]:
        """
        list(Modifier): List of the inherited modifiers
        """
        return [m for m in self.modifiers if m.contract_declarer != self]

    @property
    def modifiers_declared(self) -> List["Modifier"]:
        """
        list(Modifier): List of the modifiers defined within the contract (not inherited)
        """
        return [m for m in self.modifiers if m.contract_declarer == self]

    @property
    def functions_and_modifiers(self) -> List["Function"]:
        """
        list(Function|Modifier): List of the functions and modifiers
        """
        return self.functions + self.modifiers  # type: ignore

    @property
    def functions_and_modifiers_inherited(self) -> List["Function"]:
        """
        list(Function|Modifier): List of the inherited functions and modifiers
        """
        return self.functions_inherited + self.modifiers_inherited  # type: ignore

    @property
    def functions_and_modifiers_declared(self) -> List["Function"]:
        """
        list(Function|Modifier): List of the functions and modifiers defined within the contract (not inherited)
        """
        return self.functions_declared + self.modifiers_declared  # type: ignore

    def available_elements_from_inheritances(
            self,
            elements: Dict[str, "Function"],
            getter_available: Callable[["Contract"], List["Function"]],
    ) -> Dict[str, "Function"]:
        """

        :param elements: dict(canonical_name -> elements)
        :param getter_available: fun x
        :return:
        """
        # keep track of the contracts visited
        # to prevent an ovveride due to multiple inheritance of the same contract
        # A is B, C, D is C, --> the second C was already seen
        inherited_elements: Dict[str, "Function"] = {}
        accessible_elements = {}
        contracts_visited = []
        for father in self.inheritance_reverse:
            functions: Dict[str, "Function"] = {
                v.full_name: v
                for v in getter_available(father)
                if v.contract not in contracts_visited
            }
            contracts_visited.append(father)
            inherited_elements.update(functions)

        for element in inherited_elements.values():
            accessible_elements[element.full_name] = elements[element.canonical_name]

        return accessible_elements

    # endregion
    ###################################################################################
    ###################################################################################
    # region Inheritance
    ###################################################################################
    ###################################################################################

    @property
    def inheritance(self) -> List["Contract"]:
        """
        list(Contract): Inheritance list. Order: the first elem is the first father to be executed
        """
        return list(self._inheritance)

    @property
    def immediate_inheritance(self) -> List["Contract"]:
        """
        list(Contract): List of contracts immediately inherited from (fathers). Order: order of declaration.
        """
        return list(self._immediate_inheritance)

    @property
    def inheritance_reverse(self) -> List["Contract"]:
        """
        list(Contract): Inheritance list. Order: the last elem is the first father to be executed
        """
        return list(reversed(self._inheritance))

    def set_inheritance(
            self,
            inheritance: List["Contract"],
            immediate_inheritance: List["Contract"],
            called_base_constructor_contracts: List["Contract"],
    ):
        self._inheritance = inheritance
        self._immediate_inheritance = immediate_inheritance
        self._explicit_base_constructor_calls = called_base_constructor_contracts

    @property
    def derived_contracts(self) -> List["Contract"]:
        """
        list(Contract): Return the list of contracts derived from self
        """
        candidates = self.compilation_unit.contracts
        return [c for c in candidates if self in c.inheritance]

    # endregion
    ###################################################################################
    ###################################################################################
    # region Getters from/to object
    ###################################################################################
    ###################################################################################

    def get_functions_reading_from_variable(self, variable: "Variable") -> List["Function"]:
        """
        Return the functions reading the variable
        """
        return [f for f in self.functions if f.is_reading(variable)]

    def get_functions_writing_to_variable(self, variable: "Variable") -> List["Function"]:
        """
        Return the functions writting the variable
        """
        return [f for f in self.functions if f.is_writing(variable)]

    def get_function_from_signature(self, function_signature: str) -> Optional["Function"]:
        """
            Return a function from a signature
        Args:
            function_signature (str): signature of the function (without return statement)
        Returns:
            Function
        """
        return next(
            (f for f in self.functions if f.full_name == function_signature and not f.is_shadowed),
            None,
        )

    def get_modifier_from_signature(self, modifier_signature: str) -> Optional["Modifier"]:
        """
        Return a modifier from a signature

        :param modifier_signature:
        """
        return next(
            (m for m in self.modifiers if m.full_name == modifier_signature and not m.is_shadowed),
            None,
        )

    def get_function_from_canonical_name(self, canonical_name: str) -> Optional["Function"]:
        """
            Return a function from a a canonical name (contract.signature())
        Args:
            canonical_name (str): canonical name of the function (without return statement)
        Returns:
            Function
        """
        return next((f for f in self.functions if f.canonical_name == canonical_name), None)

    def get_modifier_from_canonical_name(self, canonical_name: str) -> Optional["Modifier"]:
        """
            Return a modifier from a canonical name (contract.signature())
        Args:
            canonical_name (str): canonical name of the modifier
        Returns:
            Modifier
        """
        return next((m for m in self.modifiers if m.canonical_name == canonical_name), None)

    def get_state_variable_from_name(self, variable_name: str) -> Optional["StateVariable"]:
        """
        Return a state variable from a name

        :param variable_name:
        """
        return next((v for v in self.state_variables if v.name == variable_name), None)

    def get_state_variable_from_canonical_name(
            self, canonical_name: str
    ) -> Optional["StateVariable"]:
        """
            Return a state variable from a canonical_name
        Args:
            canonical_name (str): name of the variable
        Returns:
            StateVariable
        """
        return next((v for v in self.state_variables if v.name == canonical_name), None)

    def get_structure_from_name(self, structure_name: str) -> Optional["Structure"]:
        """
            Return a structure from a name
        Args:
            structure_name (str): name of the structure
        Returns:
            Structure
        """
        return next((st for st in self.structures if st.name == structure_name), None)

    def get_structure_from_canonical_name(self, structure_name: str) -> Optional["Structure"]:
        """
            Return a structure from a canonical name
        Args:
            structure_name (str): canonical name of the structure
        Returns:
            Structure
        """
        return next((st for st in self.structures if st.canonical_name == structure_name), None)

    def get_event_from_signature(self, event_signature: str) -> Optional["Event"]:
        """
            Return an event from a signature
        Args:
            event_signature (str): signature of the event
        Returns:
            Event
        """
        return next((e for e in self.events if e.full_name == event_signature), None)

    def get_event_from_canonical_name(self, event_canonical_name: str) -> Optional["Event"]:
        """
            Return an event from a canonical name
        Args:
            event_canonical_name (str): name of the event
        Returns:
            Event
        """
        return next((e for e in self.events if e.canonical_name == event_canonical_name), None)

    def get_enum_from_name(self, enum_name: str) -> Optional["Enum"]:
        """
            Return an enum from a name
        Args:
            enum_name (str): name of the enum
        Returns:
            Enum
        """
        return next((e for e in self.enums if e.name == enum_name), None)

    def get_enum_from_canonical_name(self, enum_name) -> Optional["Enum"]:
        """
            Return an enum from a canonical name
        Args:
            enum_name (str): canonical name of the enum
        Returns:
            Enum
        """
        return next((e for e in self.enums if e.canonical_name == enum_name), None)

    def get_functions_overridden_by(self, function: "Function") -> List["Function"]:
        """
            Return the list of functions overriden by the function
        Args:
            (core.Function)
        Returns:
            list(core.Function)

        """
        candidatess = [c.functions_declared for c in self.inheritance]
        candidates = [candidate for sublist in candidatess for candidate in sublist]
        return [f for f in candidates if f.full_name == function.full_name]

    # endregion
    ###################################################################################
    ###################################################################################
    # region Recursive getters
    ###################################################################################
    ###################################################################################

    @property
    def all_functions_called(self) -> List["InternalCallType"]:
        """
        list(Function): List of functions reachable from the contract
        Includes super, and private/internal functions not shadowed
        """
        if self._all_functions_called is None:
            all_functions = [f for f in self.functions + self.modifiers if not f.is_shadowed]  # type: ignore
            all_callss = [f.all_internal_calls() for f in all_functions] + [list(all_functions)]
            all_calls = [item for sublist in all_callss for item in sublist]
            all_calls = list(set(all_calls))

            all_constructors = [c.constructor for c in self.inheritance if c.constructor]
            all_constructors = list(set(all_constructors))

            set_all_calls = set(all_calls + list(all_constructors))

            self._all_functions_called = [c for c in set_all_calls if isinstance(c, Function)]
        return self._all_functions_called

    @property
    def all_state_variables_written(self) -> List["StateVariable"]:
        """
        list(StateVariable): List all of the state variables written
        """
        all_state_variables_writtens = [
            f.all_state_variables_written() for f in self.functions + self.modifiers  # type: ignore
        ]
        all_state_variables_written = [
            item for sublist in all_state_variables_writtens for item in sublist
        ]
        return list(set(all_state_variables_written))

    @property
    def all_state_variables_read(self) -> List["StateVariable"]:
        """
        list(StateVariable): List all of the state variables read
        """
        all_state_variables_reads = [
            f.all_state_variables_read() for f in self.functions + self.modifiers  # type: ignore
        ]
        all_state_variables_read = [
            item for sublist in all_state_variables_reads for item in sublist
        ]
        return list(set(all_state_variables_read))

    @property
    def all_library_calls(self) -> List["LibraryCallType"]:
        """
        list((Contract, Function): List all of the libraries func called
        """
        all_high_level_callss = [f.all_library_calls() for f in self.functions + self.modifiers]  # type: ignore
        all_high_level_calls = [item for sublist in all_high_level_callss for item in sublist]
        return list(set(all_high_level_calls))

    @property
    def all_high_level_calls(self) -> List["HighLevelCallType"]:
        """
        list((Contract, Function|Variable)): List all of the external high level calls
        """
        all_high_level_callss = [f.all_high_level_calls() for f in self.functions + self.modifiers]  # type: ignore
        all_high_level_calls = [item for sublist in all_high_level_callss for item in sublist]
        return list(set(all_high_level_calls))

    # endregion
    ###################################################################################
    ###################################################################################
    # region Summary information
    ###################################################################################
    ###################################################################################

    def get_summary(self, include_shadowed=True) -> Tuple[str, List[str], List[str], List, List]:
        """Return the function summary

        :param include_shadowed: boolean to indicate if shadowed functions should be included (default True)
        Returns:
            (str, list, list, list, list): (name, inheritance, variables, fuction summaries, modifier summaries)
        """
        func_summaries = [
            f.get_summary() for f in self.functions if (not f.is_shadowed or include_shadowed)
        ]
        modif_summaries = [
            f.get_summary() for f in self.modifiers if (not f.is_shadowed or include_shadowed)
        ]
        return (
            self.name,
            [str(x) for x in self.inheritance],
            [str(x) for x in self.variables],
            func_summaries,
            modif_summaries,
        )

    def is_signature_only(self) -> bool:
        """Detect if the contract has only abstract functions

        Returns:
            bool: true if the function are abstract functions
        """
        return all((not f.is_implemented) for f in self.functions)

    # endregion
    ###################################################################################
    ###################################################################################
    # region ERC conformance
    ###################################################################################
    ###################################################################################

    def ercs(self) -> List[str]:
        """
        Return the ERC implemented
        :return: list of string
        """
        all_erc = [
            ("ERC20", self.is_erc20),
            ("ERC165", self.is_erc165),
            ("ERC1820", self.is_erc1820),
            ("ERC223", self.is_erc223),
            ("ERC721", self.is_erc721),
            ("ERC777", self.is_erc777),
        ]

        return [erc for erc, is_erc in all_erc if is_erc()]

    def is_erc20(self) -> bool:
        """
            Check if the contract is an erc20 token

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc20
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC20_signatures)

    def is_erc165(self) -> bool:
        """
            Check if the contract is an erc165 token

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc165
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC165_signatures)

    def is_erc1820(self) -> bool:
        """
            Check if the contract is an erc1820

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc165
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC1820_signatures)

    def is_erc223(self) -> bool:
        """
            Check if the contract is an erc223 token

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc223
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC223_signatures)

    def is_erc721(self) -> bool:
        """
            Check if the contract is an erc721 token

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc721
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC721_signatures)

    def is_erc777(self) -> bool:
        """
            Check if the contract is an erc777

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc165
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC777_signatures)

    def is_erc1155(self) -> bool:
        """
            Check if the contract is an erc1155

            Note: it does not check for correct return values
        :return: Returns a true if the contract is an erc1155
        """
        full_names = self.functions_signatures
        return all(s in full_names for s in ERC1155_signatures)

    @property
    def is_token(self) -> bool:
        """
        Check if the contract follows one of the standard ERC token
        :return:
        """
        return (
                self.is_erc20()
                or self.is_erc721()
                or self.is_erc165()
                or self.is_erc223()
                or self.is_erc777()
                or self.is_erc1155()
        )

    def is_possible_erc20(self) -> bool:
        """
        Checks if the provided contract could be attempting to implement ERC20 standards.

        :return: Returns a boolean indicating if the provided contract met the token standard.
        """
        # We do not check for all the functions, as name(), symbol(), might give too many FPs
        full_names = self.functions_signatures
        return (
                "transfer(address,uint256)" in full_names
                or "transferFrom(address,address,uint256)" in full_names
                or "approve(address,uint256)" in full_names
        )

    def is_possible_erc721(self) -> bool:
        """
        Checks if the provided contract could be attempting to implement ERC721 standards.

        :return: Returns a boolean indicating if the provided contract met the token standard.
        """
        # We do not check for all the functions, as name(), symbol(), might give too many FPs
        full_names = self.functions_signatures
        return (
                "ownerOf(uint256)" in full_names
                or "safeTransferFrom(address,address,uint256,bytes)" in full_names
                or "safeTransferFrom(address,address,uint256)" in full_names
                or "setApprovalForAll(address,bool)" in full_names
                or "getApproved(uint256)" in full_names
                or "isApprovedForAll(address,address)" in full_names
        )

    @property
    def is_possible_token(self) -> bool:
        """
        Check if the contract is a potential token (it might not implement all the functions)
        :return:
        """
        return self.is_possible_erc20() or self.is_possible_erc721()

    # endregion
    ###################################################################################
    ###################################################################################
    # region Dependencies
    ###################################################################################
    ###################################################################################

    def is_from_dependency(self) -> bool:
        return self.compilation_unit.core.crytic_compile.is_dependency(
            self.source_mapping["filename_absolute"]
        )

    # endregion
    ###################################################################################
    ###################################################################################
    # region Test
    ###################################################################################
    ###################################################################################

    @property
    def is_truffle_migration(self) -> bool:
        """
        Return true if the contract is the Migrations contract needed for Truffle
        :return:
        """
        if self.compilation_unit.core.crytic_compile.platform == PlatformType.TRUFFLE:
            if self.name == "Migrations":
                paths = Path(self.source_mapping["filename_absolute"]).parts
                if len(paths) >= 2:
                    return paths[-2] == "contracts" and paths[-1] == "migrations.sol"
        return False

    @property
    def is_test(self) -> bool:
        return is_test_contract(self) or self.is_truffle_migration

    # endregion
    ###################################################################################
    ###################################################################################
    # region Function analyses
    ###################################################################################
    ###################################################################################

    def update_read_write_using_ssa(self):
        for function in self.functions + self.modifiers:
            function.update_read_write_using_ssa()

    # endregion
    ###################################################################################
    ###################################################################################
    # region Upgradeability
    ###################################################################################
    ###################################################################################

    @property
    def is_upgradeable(self) -> bool:
        if self._is_upgradeable is None:
            self._is_upgradeable = False
            if self.is_upgradeable_proxy:
                return False
            initializable = self.compilation_unit.get_contract_from_name("Initializable")
            if initializable:
                if initializable in self.inheritance:
                    self._is_upgradeable = True
            else:
                for c in self.inheritance + [self]:
                    # This might lead to false positive
                    lower_name = c.name.lower()
                    if "upgradeable" in lower_name or "upgradable" in lower_name:
                        self._is_upgradeable = True
                        break
                    if "initializable" in lower_name:
                        self._is_upgradeable = True
                        break
        return self._is_upgradeable

    @property
    def is_upgradeable_proxy(self) -> bool:
        """
        Determines if a proxy contract can be upgraded, i.e. if there's an implementation address setter for upgrading

        :return: True if an implementation setter is found, or if the implementation getter suggests upgradeability
        """
        from slither.core.cfg.node import NodeType
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.declarations.function_contract import FunctionContract
        from slither.core.expressions.expression_typed import ExpressionTyped
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.identifier import Identifier

        print_debug = True
        if print_debug:
            print("Begin " + self.name + ".is_upgradeable_proxy")

        if self._is_upgradeable_proxy is None:
            if print_debug:
                print("\nChecking contract: " + self.name)
            self._is_upgradeable_proxy = False
            # calling self.is_proxy returns True or False, and should also set self._delegates_to in the process
            if self.is_proxy and self._delegates_to is not None:
                
                # if the destination is a constant, return false
                if self._delegates_to.is_constant:
                    if print_debug:
                        print("Call destination " + str(self._delegates_to) + " is constant\n")
                    self._is_upgradeable_proxy = False
                    return False
                
                # now find setter in the contract. If succeed, then the contract is upgradeable.
                if print_debug:
                    print(self.name + " is delegating to " + str(self._delegates_to) + "\nLooking for setter\n")
                if self._proxy_impl_setter is None:
                    if isinstance(self._delegates_to, StateVariable) and self._delegates_to.contract != self:
                        self._proxy_impl_setter = self.find_setter_in_contract(self._delegates_to.contract,
                                                                               self._delegates_to,
                                                                               self._proxy_impl_slot, print_debug)
                    else:
                        self._proxy_impl_setter = self.find_setter_in_contract(self, self._delegates_to,
                                                                               self._proxy_impl_slot, print_debug)
                if self._proxy_impl_setter is not None:
                    if print_debug and isinstance(self._proxy_impl_setter, FunctionContract):
                        print("\nImplementation set by function: " + self._proxy_impl_setter.name + " in contract: "
                              + self._proxy_impl_setter.contract.name)
                    self._is_upgradeable_proxy = True
                elif print_debug:
                    print("\nCould not find implementation setter in " + self.name)
                
                # then find getter
                if print_debug:
                    print("Looking for getter\n")
                if self._proxy_impl_getter is None:
                    if isinstance(self._delegates_to, StateVariable) and self._delegates_to.contract != self:
                        self._proxy_impl_getter = self.find_getter_in_contract(self._delegates_to.contract,
                                                                               self._delegates_to, print_debug)
                    else:
                        self._proxy_impl_getter = self.find_getter_in_contract(self, self._delegates_to, print_debug)
                
                # if both setter and getter can be found, then return true
                # Otherwise, at least the getter's return is non-constant
                if self._proxy_impl_getter is not None:
                    if self._proxy_impl_setter is not None:
                        self._is_upgradeable_proxy = True
                        return self._is_upgradeable_proxy
                    else:
                        return self.getter_return_is_non_constant(print_debug)
                else:
                    """
                    Handle the case, as in EIP 1822, where the Proxy has no implementation getter because it is
                    loaded explicitly from a hard-coded slot within the fallback itself.
                    We assume in this case that, if the Proxy needs to load the implementation address from storage slot
                    then the address must not be constant - otherwise why not use a constant address
                    This is only necessary if the Proxy also doesn't have an implementation setter, because it is
                    located in another contract. The assumption is only necessary if we do not search cross-contracts.
                    """
                    if print_debug:
                        print("Could not find implementation getter")
                    for n in self.fallback_function.all_nodes():
                        print(n.type)
                        if n.type == NodeType.VARIABLE: # and n.variable_declaration == self._delegates_to:
                            print(n.variable_declaration)
                            print(n.expression)
                        elif n.type == NodeType.EXPRESSION:
                            print(n.expression)
                        elif n.type == NodeType.ASSEMBLY:
                            inline_asm = n.inline_asm
                            if inline_asm and "sload" in inline_asm and self._delegates_to.name in inline_asm:
                                print(inline_asm)
                                self._is_upgradeable_proxy = True
        if print_debug:
            print("\nEnd " + self.name + ".is_upgradeable_proxy\n")
        return self._is_upgradeable_proxy

    @property
    def is_proxy(self) -> bool:
        """
        Checks for 'delegatecall' in the fallback function CFG, setting self._is_proxy = True if found.
        Also tries to set self._delegates_to: Variable in the process.

        :return: True if 'delegatecall' is found in fallback function, otherwise False
        """
        from slither.core.cfg.node import NodeType

        print_debug = True
        if print_debug:
            print("\nBegin " + self.name + ".is_proxy\n")

        if self._is_proxy is None:
            self._is_proxy = False

            if self.fallback_function is None:
                print("\nEnd " + self.name + ".is_proxy\n")
                return self._is_proxy

            self._delegates_to = None
            for node in self.fallback_function.all_nodes():
                if print_debug:
                    print(str(node.type))
                # first try to find a delegetecall in non-assembly code region
                is_proxy, self._delegates_to = self.find_delegatecall_in_ir(node, print_debug)
                if not self._is_proxy:
                    self._is_proxy = is_proxy
                if self._is_proxy and self._delegates_to is not None:
                    break

                # then try to find delegatecall in assembly region
                if node.type == NodeType.ASSEMBLY:
                    """
                    Calls self.find_delegatecall_in_asm to search in an assembly CFG node.
                    That method cannot always find the delegates_to Variable for solidity versions >= 0.6.0
                    """
                    if print_debug:
                        print("\nFound Assembly Node\n")
                    if node.inline_asm:
                        # print("\nFound Inline ASM\n")
                        is_proxy, self._delegates_to = self.find_delegatecall_in_asm(node.inline_asm, node.function)
                        if not self._is_proxy:
                            self._is_proxy = is_proxy
                        if self._is_proxy and self._delegates_to is not None:
                            break
                elif node.type == NodeType.EXPRESSION:
                    is_proxy, self._delegates_to = self.handle_assembly_in_version_0_6_0_and_above(node, print_debug)
                    if not self._is_proxy:
                        self._is_proxy = is_proxy
                    if self._is_proxy and self._delegates_to is not None:
                        break
        if print_debug:
            print("\nEnd " + self.name + ".is_proxy\n")
        return self._is_proxy

    """
    Getters for attributes set by self.is_proxy and self.is_upgradeable_proxy
    """
    @property
    def delegates_to(self) -> Optional["Variable"]:
        if self.is_proxy:
            return self._delegates_to
        return self._delegates_to

    @property
    def proxy_implementation_setter(self) -> Optional["Function"]:
        if self.is_upgradeable_proxy:
            return self._proxy_impl_setter
        return self._proxy_impl_setter

    @property
    def proxy_implementation_getter(self) -> Optional["Function"]:
        if self.is_upgradeable_proxy:
            return self._proxy_impl_getter
        return self._proxy_impl_getter

    @property
    def proxy_impl_storage_offset(self) -> Optional["Variable"]:
        return self._proxy_impl_slot

    def find_delegatecall_in_asm(
            self,
            inline_asm: Union[str, Dict],
            parent_func: Function):
        """
        Called by self.is_proxy to help find 'delegatecall' in an inline assembly block,
        as well as the address Variable which the 'delegatecall' targets.
        It is necessary to handle two separate cases, for contracts using Solidity versions
        < 0.6.0 and >= 0.6.0, due to a change in how assembly is represented after compiling,
        i.e. as an AST for versions >= 0.6.0 and as a simple string for earlier versions.

        :param inline_asm: The assembly code as either a string or an AST, depending on the solidity version
        :param parent_func: The function associated with the assembly node (may be another function called by fallback)
        :return: True if delegatecall is found, plus Variable delegates_to (if found)
        """

        print_debug = True
        is_proxy = False
        delegates_to: Variable = None
        asm_split = None
        dest = None

        if print_debug:
            print("\nBegin " + self.name + ".find_delegatecall_in_asm\n")
        if "AST" in inline_asm and isinstance(inline_asm, Dict):
            # @webthethird: inline_asm is a Yul AST for versions >= 0.6.0
            # see tests/proxies/ExampleYulAST.txt for an example
            for statement in inline_asm["AST"]["statements"]:
                if statement["nodeType"] == "YulExpressionStatement":
                    statement = statement["expression"]
                if statement["nodeType"] == "YulVariableDeclaration":
                    statement = statement["value"]
                if statement["nodeType"] == "YulFunctionCall":
                    if statement["functionName"]["name"] == "delegatecall":
                        is_proxy = True
                        args = statement["arguments"]
                        dest = args[1]
                        if dest["nodeType"] == "YulIdentifier":
                            dest = dest["name"]
                        if print_debug:
                            print("\nFound delegatecall in YulFunctionCall\n")
                            print("Destination param is called '" + dest + "'\nLooking for corresponding Variable\n")
                            print("Current function: " + parent_func.name)
                        break
        else:
            asm_split = inline_asm.split("\n")
            dest = None
            for asm in asm_split:
                if print_debug:
                    print(asm)
                if "delegatecall" in asm:
                    is_proxy = True   # Now look for the target of this delegatecall
                    params = asm.split("delegatecall(")[1].split(", ")
                    dest: str = params[1]
                    # Target should be 2nd parameter, but 1st param might have 2 params
                    # i.e. delegatecall(sub(gas, 10000), _dst, free_ptr, calldatasize, 0, 0)
                    if dest.startswith("sload("):
                        # TODO: find self._proxy_impl_slot from here
                        dest = dest.replace(")", "(").split("(")[1]
                    if dest.endswith(")"):
                        dest = params[2]
                    if print_debug:
                        print("\nFound delegatecall in inline asm")
                        print("Destination param is called '" + dest + "'\nLooking for corresponding Variable\n")
                        print("Current function: " + parent_func.name)
                    break
        if is_proxy and delegates_to is None and dest is not None:
            """
            Now that we extracted the name of the address variable passed as the second parameter to delegatecall, 
            we need to find the correct Variable object to ultimately assign to self._delegates_to.
            """
            delegates_to = self.find_delegate_variable_from_name(dest, parent_func, print_debug)
            if delegates_to is None and asm_split is not None:
                delegates_to = self.find_delegate_sloaded_from_hardcoded_slot(asm_split, dest, print_debug)
        if print_debug:
            print("\nEnd " + self.name + ".find_delegatecall_in_asm\n")
        return is_proxy, delegates_to

    def find_delegate_variable_from_name(
            self,
            dest: str,
            parent_func: Function,
            print_debug: bool
    ) -> Optional["Variable"]:
        """
        Called by find_delegatecall_in_asm, which can only extract the name of the destination variable, not the object.
        Looks in every possible place for a Variable object with exactly the same name as extracted.
        If it's a state variable, our work is done here.
        But it may also be a local variable declared within the function, or a parameter declared in its signature.
        In which case, we need to track it further, but at that point we can stop using names.

        :param dest: The name of the delegatecall destination, as a string extracted from assembly
        """
        from slither.core.cfg.node import NodeType
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.index_access import IndexAccess
        from slither.core.expressions.identifier import Identifier

        delegate = None
        if print_debug:
            print("\nBegin " + self.name + ".find_delegate_variable_from_name\n")
            print("Searching State Variables")
        for sv in self.state_variables:
            if print_debug:
                print("Checking " + sv.name)
            if sv.name == dest:
                delegate = sv
                if print_debug:
                    print(dest + " is a State Variable in contract " + sv.contract.name)
                    print("\nEnd " + self.name + ".find_delegate_variable\n")
                return delegate
        if print_debug:
            print("\nSearching Local Variables")
        for lv in parent_func.local_variables:
            if print_debug:
                print("Checking " + lv.name)
            if lv.name == dest:
                if print_debug:
                    print(dest + " is a Local Variable in " + self.name + "." + parent_func.name)
                if lv.expression is not None:
                    exp = lv.expression
                    if print_debug:
                        print("Expression: " + str(exp))
                    if isinstance(exp, Identifier):
                        val = exp.value
                        if print_debug:
                            print("Identifier value: " + str(val))
                        if isinstance(val, StateVariable):
                            delegate = val
                            if print_debug:
                                print(val.name + " is a State Variable in contract " + val.contract.name)
                                print("\nEnd " + self.name + ".find_delegate_variable\n")
                            return delegate
                    elif isinstance(exp, CallExpression):
                        """
                        Must be the getter, but we still need a variable
                        """
                        delegate = self.find_delegate_from_call_exp(exp, print_debug)
                        if print_debug:
                            print("Call Expression")
                            print("\nEnd " + self.name + ".find_delegate_variable\n")
                    elif isinstance(exp, IndexAccess):
                        exp = exp.expression_left
                        if isinstance(exp, Identifier):
                            val = exp.value
                            if isinstance(val, StateVariable):
                                delegate = val
                                if print_debug:
                                    print(val.name + " is a State Variable in contract " + val.contract.name)
                                    print("\nEnd " + self.name + ".find_delegate_variable\n")
                                return delegate
                else:
                    if print_debug:
                        print("No expression found for " + dest)
        if print_debug:
            print("\nSearching Parameter Variables")
        for idx, pv in enumerate(parent_func.parameters):
            if print_debug:
                print("Checking " + pv.name)
            if pv.name == dest:
                delegate = pv
                if print_debug:
                    print(dest + " is a Parameter in " + self.name + "." + parent_func.name)
                for n in self.fallback_function.all_nodes():
                    if n.type == NodeType.EXPRESSION:
                        exp = n.expression
                        if isinstance(exp, CallExpression):
                            called = exp.called
                            if isinstance(called, Identifier) and called.value == parent_func:
                                if print_debug:
                                    print("Found where " + parent_func.name + " is called: " + str(exp))
                                arg = exp.arguments[idx]
                                if isinstance(arg, Identifier):
                                    v = arg.value
                                    if isinstance(v, StateVariable):
                                        if print_debug:
                                            print(v.name + " is a State Variable")
                                        delegate = v
                                        break
                                    elif isinstance(v, LocalVariable) and v.expression is not None:
                                        exp = v.expression
                                        if print_debug:
                                            print(v.name + " is a Local Variable with the expression: " + str(exp))
                                        if isinstance(exp, Identifier) and isinstance(exp.value, StateVariable):
                                            delegate = exp.value
                                        elif isinstance(exp, CallExpression):
                                            delegate = self.find_delegate_from_call_exp(exp, print_debug)
                                elif isinstance(arg, CallExpression):
                                    _delegate = self.find_delegate_from_call_exp(arg, print_debug)
                                    if _delegate is not None:
                                        delegate = _delegate
                                        break
                break
        if print_debug:
            print("\nEnd " + self.name + ".find_delegate_variable_from_name\n")
        return delegate

    def find_delegate_from_call_exp(self, exp, print_debug) -> Optional["Variable"]:
        """
        Called by self.find_delegate_variable_from_name
        Having found a LocalVariable matching the destination name extracted from the delegatecall,
        we know that the value of the local variable is gotten by the given CallExpression.
        Therefore, we are interested in tracking the origin of the value returned by the Function being called.
        There are 2 ways to return values from a function in Solidity:
            1 - explicitly assigning values to named return variables, i.e.
                function _implementation() internal view returns (address impl) {
                    bytes32 slot = IMPLEMENTATION_SLOT;
                    assembly {
                        impl := sload(slot)
                    }
                }
            2 - returning values directly using a return statement (in which case variable names may be omitted), i.e.
                function implementation() public view returns (address) {
                    return getAppBase(appId());
                }
        Given this fact, without knowing anything about the pattern, we know that we must approach this in 1 of 2 ways:
            1 - If the return value is named, then take that Variable object and look for where it is assigned a value
            2 - If it has no name, find the RETURN node at the end of the function's CFG, determine which Variable
                object it is returning, then look for where it is assigned a value
        For expediency, check #2 first
        """
        from slither.core.cfg.node import NodeType
        from slither.core.variables.variable import Variable
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.tuple_expression import TupleExpression
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.expressions.identifier import Identifier
        from slither.core.declarations.function_contract import FunctionContract
        from slither.analyses.data_dependency import data_dependency

        if print_debug:
            print("\nBegin " + self.name + ".find_delegate_from_call_exp\n")
            print(exp)
        delegate: Variable = None
        func: Function = None
        ret: Variable = None
        if isinstance(exp, CallExpression):     # Guaranteed but type checking never hurts and helps IDE w autocomplete
            called = exp.called
            if isinstance(called, Identifier):  # Always the case, kind of annoying extra layer
                val = called.value
                if isinstance(val, Function):   # Identifier.value is usually a Variable but here it's always a Function
                    func = val
        if func is not None:
            if len(func.all_nodes()) == 0:
                # Sometimes Slither connects a CallExpression to an abstract function, missing the overriding function
                if print_debug:
                    print("Got abstract function, looking for overriding function")
                func = self.get_function_from_signature(func.full_name)
                if len(func.all_nodes()) > 0:
                    if print_debug:
                        print("Success")
                else:
                    if print_debug:
                        print("Failure")

            ret = func.returns[0]
            if ret.name is None or ret.name == "":
                # Case #2 - need to find RETURN node and the variable returned first
                for n in func.all_nodes():
                    if n.type == NodeType.RETURN:
                        rex = n.expression
                        if isinstance(rex, Identifier) and isinstance(rex.value, Variable):
                            if print_debug:
                                print(rex)
                            ret = rex.value
                            break
                        elif isinstance(rex, CallExpression):
                            if print_debug:
                                print("Encountered call expression at RETURN node: " + str(rex))
                            called = rex.called
                            if isinstance(called, MemberAccess):
                                if print_debug:
                                    print("Encountered member access expression: " + str(called))
                                delegate = self.find_delegate_from_member_access(called, print_debug)
                                if delegate is None:
                                    delegate = LocalVariable()
                                    delegate.expression = rex
                                    if delegate.name is None:
                                        delegate.name = str(called)
                                if print_debug:
                                    print("\nEnd " + self.name + ".find_delegate_from_call_exp\n")
                                return delegate
                            elif isinstance(called, Identifier):
                                if isinstance(called.value, FunctionContract) and called.value.contract != self:
                                    if print_debug:
                                        print("Encountered call to another contract: " + str(rex))
                            else:
                                return self.find_delegate_from_call_exp(rex, print_debug)
            else:
                # Case #1 - return variable is named, so it's initialized in the entry point with no value assigned
                for n in func.all_nodes():
                    if n.type == NodeType.EXPRESSION:
                        e = n.expression
                        if isinstance(e, AssignmentOperation):
                            if print_debug:
                                print("AssignmentOperation: " + str(e))
                            l = e.expression_left
                            r = e.expression_right
                            if isinstance(l, Identifier) and l.value == ret:
                                if isinstance(r, CallExpression):
                                    if print_debug:
                                        print("CallExpression")
                                        print(r.called)
                                    ret.expression = r
                                    if str(r.called) == "sload(uint256)":
                                        delegate = ret
                                        arg = r.arguments[0]
                                        if isinstance(arg, Identifier):
                                            v = arg.value
                                            if isinstance(v, Variable) and v.is_constant:
                                                self._proxy_impl_slot = v
                                                if print_debug:
                                                    print("Found storage slot: " + v.name)
                                            elif isinstance(v, LocalVariable) and v.expression is not None:
                                                e = v.expression
                                                if isinstance(e, Identifier) and e.value.is_constant:
                                                    self._proxy_impl_slot = e.value
                                                    if print_debug:
                                                        print("Found storage slot: " + e.value.name)
            if print_debug:
                print(func.name + " returns a variable of type " + str(ret.type)
                      + ((" called " + ret.name) if ret.name != "" else ""))
            if isinstance(ret, StateVariable):
                delegate = ret
            elif func.contains_assembly:
                if print_debug:
                    print(func.name + " contains assembly - looking for sload")
                for n in func.all_nodes():
                    if delegate is not None:
                        break
                    if n.type == NodeType.ASSEMBLY and isinstance(n.inline_asm, str):
                        # only handle versions < 0.6.0 here - otherwise use EXPRESSION nodes
                        if print_debug:
                            print("Looking in ASSEMBLY node")
                        asm_split = n.inline_asm.split("\n")
                        for asm in asm_split:
                            if print_debug:
                                print(asm)
                            if ret.name + " := sload(" in asm:
                                if print_debug:
                                    print("Return value set by sload in asm")
                                delegate = ret
                                slotname = asm.split("sload(")[1].strip(")")
                                for v in func.variables_read_or_written:
                                    if v.name == slotname:
                                        if isinstance(v, StateVariable) and v.is_constant:
                                            self._proxy_impl_slot = v
                                            if print_debug:
                                                print("Found storage slot: " + v.name)
                                        elif isinstance(v, LocalVariable) and v.expression is not None:
                                            e = v.expression
                                            if isinstance(e, Identifier) and e.value.is_constant:
                                                self._proxy_impl_slot = e.value
                                                if print_debug:
                                                    print("Found storage slot: " + e.value.name)
                                break
                    elif n.type == NodeType.EXPRESSION and ret.name in str(n.expression):
                        # handle versions >= 0.6.0
                        if print_debug:
                            print("Looking in EXPRESSION node")
                        e = n.expression
                        if isinstance(e, AssignmentOperation):
                            if print_debug:
                                print("Assignment operation: " + str(e))
                            l = e.expression_left
                            r = e.expression_right
                            if isinstance(l, Identifier) and l.value == ret:
                                if print_debug:
                                    print("Found " + ret.name + " on left side of assignment")
                                if isinstance(r, CallExpression) and "sload" in str(r):
                                    delegate = ret
                                    arg = r.arguments[0]
                                    if isinstance(arg, Identifier):
                                        v = arg.value
                                        if isinstance(v, StateVariable) and v.is_constant:
                                            self._proxy_impl_slot = v
                                            if print_debug:
                                                print("Found storage slot: " + v.name)
                                        elif isinstance(v, LocalVariable) and v.expression is not None:
                                            e = v.expression
                                            if isinstance(e, Identifier) and e.value.is_constant:
                                                self._proxy_impl_slot = e.value
                                                if print_debug:
                                                    print("Found storage slot: " + e.value.name)
                                    break
            elif isinstance(ret, LocalVariable):
                if print_debug:
                    print("Return value is LocalVariable: " + ret.name)
                if ret.expression is not None:
                    e = ret.expression
                    if print_debug:
                        print("Return expression: " + str(e))
                    if isinstance(e, CallExpression):
                        called = e.called
                        print("CallExpression: " + str(called))
                        if isinstance(called, Identifier):
                            val = called.value
                            print("Identifier: " + str(val))
                            if isinstance(val, FunctionContract):
                                if print_debug:
                                    print(val.contract.name + "." + val.full_name)
                                if val.contract != self:
                                    delegate = ret
                        elif isinstance(called, MemberAccess):
                            print("MemberAccess: " + str(called))
                            if str(called) == "abi.decode":
                                arg = e.arguments[0]
                                if isinstance(arg, Identifier):
                                    val = arg.value
                                    print(val)
                                    for n in func.all_nodes():
                                        if n.type == NodeType.EXPRESSION:
                                            e = n.expression
                                            if isinstance(e, AssignmentOperation):
                                                if print_debug:
                                                    print("AssignmentOperation: " + str(e))
                                                l = e.expression_left
                                                r = e.expression_right
                                                if isinstance(l, Identifier) and l.value == val:
                                                    ret.expression = r
                                                    break
                                                elif isinstance(l, TupleExpression):
                                                    for v in l.expressions:
                                                        if isinstance(v, Identifier) and v.value == val:
                                                            ret.expression = r
                                                            break
                                    e = ret.expression
                                    if isinstance(e, CallExpression) and isinstance(e.called, MemberAccess):
                                        delegate = self.find_delegate_from_member_access(e, print_debug)
                            else:
                                delegate = self.find_delegate_from_member_access(called, print_debug)
                else:
                    if print_debug:
                        print("has no expression")
        if print_debug:
            print("\nEnd " + self.name + ".find_delegate_from_call_exp\n")
        return delegate

    def find_delegate_from_member_access(self, exp, print_debug) -> Optional["Variable"]:
        from slither.core.cfg.node import NodeType
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.identifier import Identifier
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.type_conversion import TypeConversion
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.solidity_types.user_defined_type import UserDefinedType
        from slither.core.solidity_types.elementary_type import ElementaryType

        if print_debug:
            print("\nBegin " + self.name + ".find_delegate_from_member_access\n")
            print("Expression: " + str(exp))
        delegate: Variable = None
        contract: Contract = None
        member_name = None
        args = None
        if isinstance(exp, CallExpression) and isinstance(exp.called, MemberAccess):
            args = exp.arguments
            exp = exp.called
        if isinstance(exp, MemberAccess):
            member_name = exp.member_name
            e = exp.expression
            if isinstance(e, TypeConversion) or isinstance(e, Identifier):
                ctype = e.type
                if isinstance(e, Identifier):
                    ctype = e.value.type
                if isinstance(ctype, UserDefinedType) and isinstance(ctype.type, Contract) and ctype.type != self:
                    contract = ctype.type
                    if print_debug:
                        print(member_name + " is a member of the contract type: " + contract.name)
                    if contract.is_interface:
                        if print_debug:
                            print("Which is an interface")
                        for c in self.compilation_unit.contracts:
                            if c == contract:
                                continue
                            if contract in c.inheritance:
                                if print_debug:
                                    print(c.name + " inherits " + contract.name)
                                contract = c
                        if contract.is_interface:
                            for c in self.compilation_unit.contracts:
                                if c == contract:
                                    continue
                                for f in c.functions:
                                    if f.name == member_name and str(f.return_type) == "address":
                                        contract = c
                                for v in c.state_variables:
                                    if v.name == member_name and "public" in v.visibility and "address" in str(v.type):
                                        contract = c
                # elif isinstance(ctype, ElementaryType) and str(ctype) == "address":
                #     print(str(e) + " is an address variable: " + str(e.value.expression))
                #     if member_name == "staticcall" and isinstance(args, List) and len(args) == 0:
                #         print("staticcall with no arguments - must be calling fallback in " + str(e))
        if contract is not None:
            if print_debug:
                print("Looking for " + member_name + " in " + contract.name)
            for f in contract.functions:
                if f.name == member_name:
                    if print_debug:
                        print("Found the function called " + f.name)
                    ret = f.returns[0]
                    if ret.name is None or ret.name == "":
                        for n in f.all_nodes():
                            if n.type == NodeType.RETURN:
                                e = n.expression
                                if isinstance(e, Identifier):
                                    ret = e.value
                    if isinstance(ret, StateVariable):
                        delegate = ret
                        if print_debug:
                            print("Found the return value from " + f.name)
                            print("It's a state variable in " + contract.name + " called " + delegate.name)
                    elif isinstance(ret, LocalVariable):
                        if ret.expression is None:
                            for n in f.all_nodes():
                                if n.type == NodeType.EXPRESSION:
                                    e = n.expression
                                    if isinstance(e, AssignmentOperation):
                                        l = e.expression_left
                                        r = e.expression_right
                                        if isinstance(l, Identifier) and l.value == ret:
                                            ret.expression = r
                        if ret.expression is not None:
                            e = ret.expression
                            if isinstance(e, Identifier) and isinstance(e.value, StateVariable):
                                delegate = e.value
                                if print_debug:
                                    print("Found the return value from " + f.name)
                                    print("It's a state variable in " + contract.name + " called " + delegate.name)
                            elif isinstance(e, CallExpression):
                                if print_debug:
                                    print("Found the return value from " + f.name)
                                    print("But it comes from a call expression: " + str(e))
                                delegate = contract.find_delegate_from_call_exp(e, print_debug)
            if delegate is None:
                for v in contract.state_variables:
                    if v.name == member_name and "public" in v.visibility and "address" in str(v.type):
                        delegate = v
                        break
        if print_debug:
            print("\nEnd " + self.name + ".find_delegate_from_member_access\n")
        return delegate

    def find_delegate_sloaded_from_hardcoded_slot(
            self,
            asm_split: List[str],
            dest: str,
            print_debug: bool
    ) -> Optional["Variable"]:
        """
        Finally, here I am trying to handle the case where there are no variables at all in the proxy,
        except for one defined within the assembly block itself with the slot hardcoded as seen below.
        In such an instance, there is literally no Variable object to assign to self._delegates_to,
        so we attempt to create a new one if appropriate
        ex: /tests/proxies/EIP1822Token.sol
        function() external payable {
            assembly { // solium-disable-line
                let logic := sload(0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7)
                calldatacopy(0x0, 0x0, calldatasize)
                let success := delegatecall(sub(gas, 10000), logic, 0x0, calldatasize, 0, 0)
                ...
            }
        }
        """
        from slither.core.variables.local_variable import LocalVariable, Variable
        from slither.core.solidity_types.elementary_type import ElementaryType

        if print_debug:
            print("\nBegin " + self.name + ".find_delegate_sloaded_from_hardcoded_slot\n")
        delegates_to = None
        for asm in asm_split:
            if dest in asm and "sload(" in asm:
                slot = asm.split("sload(", 1)[1].split(")")[0]
                print(slot)
                if len(slot) == 66 and slot.startswith("0x"):  # 32-bit memory address
                    delegates_to = LocalVariable()
                    delegates_to.set_type(ElementaryType("address"))
                    delegates_to.name = dest
                    delegates_to.set_location(slot)
                    impl_slot = Variable()
                    impl_slot.name = slot
                    impl_slot.is_constant = True
                    impl_slot.set_type(ElementaryType("bytes32"))
                    self._proxy_impl_slot = impl_slot
                    break
        if print_debug:
            print("\nEnd " + self.name + ".find_delegate_sloaded_from_hardcoded_slot\n")
        return delegates_to

    @staticmethod
    def find_delegatecall_in_ir(node, print_debug):     # General enough to keep as is
        """
        Handles finding delegatecall outside of an assembly block, 
        i.e. delegate.delegatecall(msg.data)  
        ex: tests/proxies/Delegation.sol (appears to have been written to demonstrate a vulnerability) 
        """
        from slither.slithir.operations import LowLevelCall
        b = False
        d = None
        if print_debug:
            print("\nBegin Contract.find_delegatecall_in_ir\n")
        for ir in node.irs:
            if isinstance(ir, LowLevelCall):
                if print_debug:
                    print("\nFound LowLevelCall\n")
                if ir.function_name == "delegatecall":
                    if print_debug:
                        print("\nFound delegatecall in LowLevelCall\n")
                    b = True
                    d = ir.destination
                    break
        if print_debug:
            print("\nEnd Contract.find_delegatecall_in_ir\n")
        return b, d

    def handle_assembly_in_version_0_6_0_and_above(self, node, print_debug):
        """
        For versions >= 0.6.0, in addition to Assembly nodes as seen above, it seems that 
        Slither creates Expression nodes for expressions within an inline assembly block.
        This is convenient, because sometimes self.find_delegatecall_in_asm fails to find 
        the target Variable self._delegates_to, so this serves as a fallback for such cases.
        ex: /tests/proxies/App2.sol (for comparison, /tests/proxies/App.sol is an earlier version)
        """
        from slither.core.expressions.expression_typed import ExpressionTyped
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.index_access import IndexAccess
        from slither.core.expressions.identifier import Identifier
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.variables.state_variable import StateVariable

        is_proxy = False
        delegate_to = None
        expression = node.expression
        if print_debug:
            print("\nBegin Contract.handle_assembly_in_version_0_6_0_and_above\n")
            print("Found Expression Node: " + str(expression))
        if isinstance(expression, ExpressionTyped):
            if print_debug:
                print("Expression Type: " + str(expression.type))
            if isinstance(expression, AssignmentOperation):
                """
                Handles the common case like this: 
                let result := delegatecall(gas, implementation, 0, calldatasize, 0, 0)
                """
                expression = expression.expression_right
                if print_debug:
                    print("Checking right side of assignment expression...")
        if isinstance(expression, CallExpression):
            if print_debug:
                print("Expression called: " + str(expression.called) + "\nType of call:"
                        + expression.type_call + "\nArgs:")
                if len(expression.arguments) > 0:
                    for arg in expression.arguments:
                        print(str(arg))
            if "delegatecall" in str(expression.called):
                is_proxy = True
                if print_debug:
                    print("\nFound delegatecall in expression:\n" + str(expression.called) + "\n")
                if len(expression.arguments) > 1:
                    # @webthethird: if there's no second arg, likely a LowLevelCall, should catch above
                    dest = expression.arguments[1]
                    if print_debug:
                        print("Destination is " + str(dest))
                    if isinstance(dest, Identifier):
                        val = dest.value
                        print("dest.value: " + str(val))
                        if isinstance(val, StateVariable):
                            delegate_to = val
                        elif isinstance(val, LocalVariable):
                            exp = val.expression
                            if print_debug:
                                print("Expression: " + str(exp))
                            if exp is not None:
                                if isinstance(exp, Identifier) and isinstance(exp.value, StateVariable):
                                    delegate_to = exp.value
                                elif isinstance(exp, CallExpression):
                                    delegate_to = self.find_delegate_from_call_exp(exp, print_debug)
                                elif isinstance(exp, MemberAccess):
                                    exp = exp.expression
                                    if isinstance(exp, IndexAccess):
                                        exp = exp.expression_left
                                        if isinstance(exp, Identifier):
                                            delegate_to = val
                                        elif isinstance(exp, MemberAccess):
                                            exp = exp.expression
                                            if isinstance(exp, Identifier):
                                                delegate_to = val
                            else:
                                delegate_to = self.find_delegate_variable_from_name(val.name, node.function, print_debug)
        if print_debug:
            print("\nEnd Contract.handle_assembly_in_version_0_6_0_and_above\n")
        return is_proxy, delegate_to

    def getter_return_is_non_constant(self, print_debug) -> bool:
        """
        If we could only find the getter, but not the setter, make sure that the getter does not return
        a variable that can never be set (i.e. is practically constant, but not declared constant)
        Instead we would like to see if the getter returns the result of a call to another function,
        possibly a function in another contract.
        ex: in /tests/proxies/APMRegistry.sol, AppProxyPinned should not be identified as upgradeable,
            though AppProxyUpgradeable obviously should be
        """
        from slither.core.cfg.node import NodeType
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.identifier import Identifier
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.variables.state_variable import StateVariable
        from slither.analyses.data_dependency import data_dependency

        if print_debug:
            print("\nBegin " + self.name + ".getter_return_is_non_constant\n")
            print("Found getter function but not setter\nChecking if getter calls any other function")
        for node in self._proxy_impl_getter.all_nodes():
            exp = node.expression
            if print_debug:
                print(str(node.type) + ": " + str(exp))
            if node.type == NodeType.EXPRESSION and isinstance(exp, AssignmentOperation):
                left = exp.expression_left
                right = exp.expression_right
                if isinstance(left, Identifier) and left.value == self._delegates_to:
                    if print_debug:
                        print(right)
                    if isinstance(right, Identifier) and right.value.is_constant:
                        self._is_upgradeable_proxy = False
                        return self._is_upgradeable_proxy
                    elif isinstance(right, CallExpression):
                        print("Call Expression")
                        if "sload" in str(right):
                            slot = right.arguments[0]
                            if isinstance(slot, Identifier):
                                slot = slot.value
                                if slot.is_constant:
                                    self._proxy_impl_slot = slot
                                elif isinstance(slot, LocalVariable):
                                    for v in self.variables:
                                        if data_dependency.is_dependent(slot, v, node.function) and v.is_constant:
                                            self._proxy_impl_slot = v
                                            break
                        if self._proxy_impl_slot is not None and self._proxy_impl_setter is None:
                            for f in self.functions:
                                if f.contains_assembly:
                                    slot = None
                                    for n in f.all_nodes():
                                        if n.type == NodeType.EXPRESSION:
                                            e = n.expression
                                            if print_debug:
                                                print(e)
                                            if isinstance(e, AssignmentOperation):
                                                l = e.expression_left
                                                r = e.expression_right
                                                if isinstance(r, Identifier) and r.value == self._proxy_impl_slot:
                                                    slot = l.value
                                            elif isinstance(e, CallExpression) and str(e.called) == "sstore":
                                                if e.arguments[0] == slot or e.arguments[0] == self._proxy_impl_slot:
                                                    self._proxy_impl_setter = f
                                        elif n.type == NodeType.ASSEMBLY and n.inline_asm is not None:
                                            if "sstore(" + str(slot) in n.inline_asm \
                                                    or "sstore(" + str(self._proxy_impl_slot) in n.inline_asm:
                                                self._proxy_impl_setter = f
                        self._is_upgradeable_proxy = True
                        return self._is_upgradeable_proxy
                    elif isinstance(right, MemberAccess):
                        print("Member Access")
                        self._is_upgradeable_proxy = True
                        return self._is_upgradeable_proxy
            elif node.type == NodeType.RETURN:
                if isinstance(exp, CallExpression):
                    self._is_upgradeable_proxy = True
                    return self._is_upgradeable_proxy
        if print_debug:
            print("\nEnd " + self.name + ".getter_return_is_non_constant\n")
        return self._is_upgradeable_proxy

    @staticmethod
    def find_getter_in_contract(
            contract: "Contract", 
            var_to_get: Union[str, "Variable"],
            print_debug: bool
    ) -> Optional[Function]:
        """
        Tries to find the getter function for a given variable.
        Static because we can use this for cross-contract implementation setters, i.e. EIP 1822 Proxy/Proxiable

        :param contract: the Contract to look in
        :param var_to_get: the Variable to look for, or at least its name as a string
        :param print_debug: True to print debugging statements, False to mute
        :return: the function in contract which sets var_to_set, if found
        """
        from slither.core.cfg.node import NodeType
        from slither.core.variables.variable import Variable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.identifier import Identifier
        from slither.core.expressions.call_expression import CallExpression

        getter = None
        exp = (var_to_get.expression if isinstance(var_to_get, Variable) else None)
        if print_debug:
            print("\nBegin " + contract.name + ".find_getter_in_contract\n")
        if exp is not None and isinstance(exp, CallExpression):
            print(exp)
        for f in contract.functions:
            if contract._proxy_impl_getter is not None:
                getter = contract._proxy_impl_getter
                break
            if len(f.all_nodes()) == 0:
                continue
            if f.name is not None:
                if print_debug:
                    print("Checking function: " + f.name)
                if isinstance(exp, CallExpression) and len(f.all_nodes()) > 0:
                    if f.name == str(exp.called) or exp in f.expressions:
                        getter = f
                        if print_debug:
                            print("\n" + f.name + " appears to be the implementation getter\n")
                        break
            else:
                if print_debug:
                    print("Unnamed function of type: " + str(f.function_type))
                continue
            if not f.name == "fallback" and "constructor" not in f.name.lower():
                if len(f.returns) > 0:
                    for v in f.returns:
                        if print_debug:
                            print(f.name + " returns " + str(v.type) + " variable " +
                                  (("called " + v.name) if v.name != "" else ""))
                        if v == var_to_get:
                            if print_debug:
                                print("\n" + f.name + " appears to be the implementation getter\n")
                            getter = f
                            break
                    for n in f.all_nodes():
                        if getter is not None:
                            break
                        if n.type == NodeType.RETURN:
                            e = n.expression
                            if isinstance(e, Identifier) and e.value == var_to_get:
                                getter = f
                                break
                        if contract.proxy_impl_storage_offset is not None and f.contains_assembly:
                            slot = contract.proxy_impl_storage_offset
                            if print_debug:
                                print(f.name + " contains assembly")
                            if n.type == NodeType.ASSEMBLY and isinstance(n.inline_asm, str) and "sloa" in n.inline_asm:
                                slotname = n.inline_asm.split("sload(")[1].split(")")[0]
                                if slotname == slot.name:
                                    getter = f
                                    break
                                for v in f.variables_read_or_written:
                                    if v.name == slotname and isinstance(v, LocalVariable) and v.expression is not None:
                                        e = v.expression
                                        if isinstance(e, Identifier) and e.value == slot:
                                            getter = f
                                            break
                            elif n.type == NodeType.EXPRESSION:
                                e = n.expression
                                if isinstance(e, CallExpression) and "sload" in str(e.called):
                                    e = e.arguments[0]
                                    if isinstance(e, Identifier):
                                        v = e.value
                                        if v == slot:
                                            getter = f
                                            break
                                        elif isinstance(v, LocalVariable) and v.expression is not None:
                                            e = v.expression
                                            if isinstance(e, Identifier) and e.value == slot:
                                                getter = f
                                                break
                    if getter is not None:
                        break
        if print_debug:
            print("\nEnd " + contract.name + ".find_getter_in_contract\n")
        return getter

    @staticmethod
    def find_setter_in_contract(
            contract: "Contract",
            var_to_set: Union[str, "Variable"],
            storage_slot: Optional["Variable"],
            print_debug: bool
    ) -> Optional[Function]:
        """
        Tries to find the setter function for a given variable.
        Static because we can use this for cross-contract implementation setters, i.e. EIP 1822 Proxy/Proxiable

        :param contract: the Contract to look in
        :param var_to_set: the Variable to look for, or at least its name as a string
        :param storage_slot: an optional, constant variable containing a storage offset (for setting via sstore)
        :param print_debug: True to print debugging statements, False to mute
        :return: the function in contract which sets var_to_set, if found
        """
        from slither.core.cfg.node import NodeType
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.expression_typed import ExpressionTyped
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.identifier import Identifier

        setter = None

        if print_debug:
            print("\nBegin " + contract.name + ".find_setter_in_contract\n")
        for f in contract.functions:
            if setter is not None:
                break
            if f.name is not None:
                if print_debug:
                    print("Checking function: " + f.name)
            else:   # I don't know why but I occasionally run into unnamed functions that would crash an unchecked print
                if print_debug:
                    print("Unnamed function of type: " + str(f.function_type))
                continue
            if not f.name == "fallback" and "constructor" not in f.name.lower() and "init" not in f.name.lower() \
                    and f.name != contract.name:
                for v in f.variables_written:
                    if isinstance(v, LocalVariable) and v in f.returns:
                        if print_debug:
                            print(f.name + " returns local variable: " + v.name)
                        continue
                    elif isinstance(v, StateVariable):
                        if print_debug:
                            print(f.name + " writes to state variable: " + v.name)
                        if str(var_to_set) == v.name:
                            setter = f
                            break
                if f.contains_assembly:
                    if print_debug:
                        print(f.name + " contains assembly")
                    for node in f.all_nodes():
                        if setter is not None:
                            break
                        if node.type == NodeType.ASSEMBLY and isinstance(node.inline_asm, str):
                            inline = node.inline_asm
                            for asm in inline.split("\n"):
                                if "sstore" in asm:
                                    if print_debug:
                                        print(asm)
                                    slotname = asm.split("sstore(")[1].split(",")[0]
                                    for v in f.variables_read_or_written:
                                        if v.name == slotname:
                                            if v in [storage_slot, var_to_set]:
                                                setter = f
                                                break
                                            elif isinstance(v, LocalVariable):
                                                exp = v.expression
                                                if isinstance(exp, Identifier) and exp.value in [storage_slot,
                                                                                                 var_to_set]:
                                                    setter = f
                                                    break
                                    if setter is not None:
                                        break
                        elif node.type == NodeType.EXPRESSION:
                            exp = node.expression
                            if print_debug:
                                print(exp)
                            if isinstance(exp, CallExpression) and "sstore" in str(exp.called):
                                if print_debug:
                                    print(exp.called)
                                arg = exp.arguments[0]
                                if isinstance(arg, Identifier):
                                    v = arg.value
                                    if v in [storage_slot, var_to_set]:
                                        setter = f
                                        break
                                    elif isinstance(v, LocalVariable):
                                        exp = v.expression
                                        if isinstance(exp, Identifier) and exp.value in [storage_slot, var_to_set]:
                                            setter = f
                                            break
        # if setter is None and "facet" in str(var_to_set):
        #     """
        #     Handle the corner case for EIP-2535 Diamond proxy
        #     The function diamondCut is used to add/delete/modify logic contracts (it is the setter)
        #     But, this function is implemented in a facet (logic) contract itself, i.e. DiamondCutFacet
        #     This facet is added by the constructor, using LibDiamond.diamondCut, and subsequent calls
        #     to diamondCut are handled by the fallback(), which delegates to the DiamondCutFacet
        #     ex: /tests/proxies/DiamondFactory.sol
        #     """
        #     if print_debug:
        #         print("\nBegin DiamondCut corner case handling\n")
        #     constructor = contract.constructors_declared
        #     for n in constructor.all_nodes():
        #         if n.type == NodeType.EXPRESSION:
        #             exp = n.expression
        #             if print_debug:
        #                 print(exp)
        #                 if isinstance(exp, ExpressionTyped):
        #                     print(exp.type)
        #             if isinstance(exp, CallExpression):
        #                 print(exp.called)
        #                 if "diamondCut" in str(exp.called):
        #                     diamond_cut = exp.arguments[0]
        #                     if isinstance(diamond_cut, Identifier) and "DiamondCut" in str(diamond_cut.value.type):
        #                         idiamond_cut = contract.compilation_unit.get_contract_from_name("IDiamondCut")
        #                         cut_facet = idiamond_cut
        #                         for c in contract.compilation_unit.contracts:
        #                             if c == idiamond_cut:
        #                                 continue
        #                             if idiamond_cut in c.inheritance:
        #                                 cut_facet = c
        #                         for f in cut_facet.functions:
        #                             if f.name == "diamondCut":
        #                                 setter = f
        #                                 break
        #     if print_debug:
        #         print("\nEnd DiamondCut corner case handling\n")
        if print_debug:
            print("\nEnd " + contract.name + ".find_setter_in_contract\n")
        return setter

    # endregion
    ###################################################################################
    ###################################################################################
    # region Internals
    ###################################################################################
    ###################################################################################

    @property
    def is_incorrectly_constructed(self) -> bool:
        """
        Return true if there was an internal Slither's issue when analyzing the contract
        :return:
        """
        return self._is_incorrectly_parsed

    @is_incorrectly_constructed.setter
    def is_incorrectly_constructed(self, incorrect: bool):
        self._is_incorrectly_parsed = incorrect

    def add_constructor_variables(self):
        from slither.core.declarations.function_contract import FunctionContract

        if self.state_variables:
            for (idx, variable_candidate) in enumerate(self.state_variables):
                if variable_candidate.expression and not variable_candidate.is_constant:

                    constructor_variable = FunctionContract(self.compilation_unit)
                    constructor_variable.set_function_type(FunctionType.CONSTRUCTOR_VARIABLES)
                    constructor_variable.set_contract(self)
                    constructor_variable.set_contract_declarer(self)
                    constructor_variable.set_visibility("internal")
                    # For now, source mapping of the constructor variable is the whole contract
                    # Could be improved with a targeted source mapping
                    constructor_variable.set_offset(self.source_mapping, self.compilation_unit)
                    self._functions[constructor_variable.canonical_name] = constructor_variable

                    prev_node = self._create_node(
                        constructor_variable, 0, variable_candidate, constructor_variable
                    )
                    variable_candidate.node_initialization = prev_node
                    counter = 1
                    for v in self.state_variables[idx + 1:]:
                        if v.expression and not v.is_constant:
                            next_node = self._create_node(
                                constructor_variable, counter, v, prev_node.scope
                            )
                            v.node_initialization = next_node
                            prev_node.add_son(next_node)
                            next_node.add_father(prev_node)
                            prev_node = next_node
                            counter += 1
                    break

            for (idx, variable_candidate) in enumerate(self.state_variables):
                if variable_candidate.expression and variable_candidate.is_constant:

                    constructor_variable = FunctionContract(self.compilation_unit)
                    constructor_variable.set_function_type(
                        FunctionType.CONSTRUCTOR_CONSTANT_VARIABLES
                    )
                    constructor_variable.set_contract(self)
                    constructor_variable.set_contract_declarer(self)
                    constructor_variable.set_visibility("internal")
                    # For now, source mapping of the constructor variable is the whole contract
                    # Could be improved with a targeted source mapping
                    constructor_variable.set_offset(self.source_mapping, self.compilation_unit)
                    self._functions[constructor_variable.canonical_name] = constructor_variable

                    prev_node = self._create_node(
                        constructor_variable, 0, variable_candidate, constructor_variable
                    )
                    variable_candidate.node_initialization = prev_node
                    counter = 1
                    for v in self.state_variables[idx + 1:]:
                        if v.expression and v.is_constant:
                            next_node = self._create_node(
                                constructor_variable, counter, v, prev_node.scope
                            )
                            v.node_initialization = next_node
                            prev_node.add_son(next_node)
                            next_node.add_father(prev_node)
                            prev_node = next_node
                            counter += 1

                    break

    def _create_node(
            self, func: Function, counter: int, variable: "Variable", scope: Union[Scope, Function]
    ):
        from slither.core.cfg.node import Node, NodeType
        from slither.core.expressions import (
            AssignmentOperationType,
            AssignmentOperation,
            Identifier,
        )

        # Function uses to create node for state variable declaration statements
        node = Node(NodeType.OTHER_ENTRYPOINT, counter, scope)
        node.set_offset(variable.source_mapping, self.compilation_unit)
        node.set_function(func)
        func.add_node(node)
        assert variable.expression
        expression = AssignmentOperation(
            Identifier(variable),
            variable.expression,
            AssignmentOperationType.ASSIGN,
            variable.type,
        )

        expression.set_offset(variable.source_mapping, self.compilation_unit)
        node.add_expression(expression)
        return node

    # endregion
    ###################################################################################
    ###################################################################################
    # region SlithIR
    ###################################################################################
    ###################################################################################

    def convert_expression_to_slithir_ssa(self):
        """
        Assume generate_slithir_and_analyze was called on all functions

        :return:
        """
        from slither.slithir.variables import StateIRVariable

        all_ssa_state_variables_instances = dict()

        for contract in self.inheritance:
            for v in contract.state_variables_declared:
                new_var = StateIRVariable(v)
                all_ssa_state_variables_instances[v.canonical_name] = new_var
                self._initial_state_variables.append(new_var)

        for v in self.variables:
            if v.contract == self:
                new_var = StateIRVariable(v)
                all_ssa_state_variables_instances[v.canonical_name] = new_var
                self._initial_state_variables.append(new_var)

        for func in self.functions + self.modifiers:
            func.generate_slithir_ssa(all_ssa_state_variables_instances)

    def fix_phi(self):
        last_state_variables_instances = dict()
        initial_state_variables_instances = dict()
        for v in self._initial_state_variables:
            last_state_variables_instances[v.canonical_name] = []
            initial_state_variables_instances[v.canonical_name] = v

        for func in self.functions + self.modifiers:
            result = func.get_last_ssa_state_variables_instances()
            for variable_name, instances in result.items():
                last_state_variables_instances[variable_name] += instances

        for func in self.functions + self.modifiers:
            func.fix_phi(last_state_variables_instances, initial_state_variables_instances)

    # endregion
    ###################################################################################
    ###################################################################################
    # region Built in definitions
    ###################################################################################
    ###################################################################################

    def __eq__(self, other):
        if isinstance(other, str):
            return other == self.name
        if isinstance(other, Contract):
            """ @webthethird Implemented to resolve false positives in upgradeability > checks > variables_order
                get_summary()-> (str, list, list, list, list): 
                                [name, inheritance, variables, function summaries, modifier summaries]
            """
            self_summary = self.get_summary()
            other_summary = other.get_summary()

            """ List[str(x) for x in self.inheritance] """
            self_inherits = self_summary[1]
            other_inherits = other_summary[1]
            if len(self_inherits) != len(other_inherits):
                return False
            for i in range(len(self_inherits)):
                if self_inherits[i] != other_inherits[i]:
                    return False
            """ List[str(x) for x in self.variables] """
            self_variables = self_summary[2]
            other_variables = other_summary[2]
            if len(self_variables) != len(other_variables):
                return False
            for i in range(len(self_variables)):
                if self_variables[i] != other_variables[i]:
                    return False
            """ List[f.get_summary() for f in self.functions if (not f.is_shadowed or include_shadowed)]
                                                   0    1    2    3          4          5           6          7
                function_contract.get_summary()-> (str, str, str, list(str), list(str), listr(str), list(str), list(str)
                                                  [contract_name, name, visibility, modifiers, vars read, vars written, 
                                                   internal_calls, external_calls_as_expressions]
            """
            self_func_summaries = self_summary[3]
            other_func_summaries = other_summary[3]
            if len(self_func_summaries) != len(other_func_summaries):
                return False
            for i in range(len(self_func_summaries)):
                self_fsum = self_func_summaries[i]
                other_fsum = other_func_summaries[i]
                if self_fsum[1] != other_fsum[1]:
                    return False
                if self_fsum[2] != other_fsum[2]:
                    return False
                if len(self_fsum[3]) != len(other_fsum[3]):
                    return False
                for j in range(len(self_fsum[3])):
                    if self_fsum[3][j] != other_fsum[3][j]:
                        return False
                if len(self_fsum[4]) != len(other_fsum[4]):
                    return False
                for j in range(len(self_fsum[4])):
                    if self_fsum[4][j] != other_fsum[4][j]:
                        return False
                if len(self_fsum[5]) != len(other_fsum[5]):
                    return False
                for j in range(len(self_fsum[5])):
                    if self_fsum[5][j] != other_fsum[5][j]:
                        return False
                if len(self_fsum[6]) != len(other_fsum[6]):
                    return False
                for j in range(len(self_fsum[6])):
                    if self_fsum[6][j] != other_fsum[6][j]:
                        return False
                if len(self_fsum[7]) != len(other_fsum[7]):
                    return False
                for j in range(len(self_fsum[7])):
                    if self_fsum[7][j] != other_fsum[7][j]:
                        return False
            """ List[f.get_summary() for f in self.modifiers if (not f.is_shadowed or include_shadowed)]
                modifier.get_summary() -> function_contract.get_summary()
            """
            self_modif_summaries = self_summary[4]
            other_modif_summaries = other_summary[4]
            if len(self_modif_summaries) != len(other_modif_summaries):
                return False
            for i in range(len(self_modif_summaries)):
                self_msum = self_modif_summaries[i]
                other_msum = other_modif_summaries[i]
                if self_msum[1] != other_msum[1]:
                    return False
                if self_msum[2] != other_msum[2]:
                    return False
                if len(self_msum[3]) != len(other_msum[3]):
                    return False
                for j in range(len(self_msum[3])):
                    if self_msum[3][j] != other_msum[3][j]:
                        return False
                if len(self_msum[4]) != len(other_msum[4]):
                    return False
                for j in range(len(self_msum[4])):
                    if self_msum[4][j] != other_msum[4][j]:
                        return False
                if len(self_msum[5]) != len(other_msum[5]):
                    return False
                for j in range(len(self_msum[5])):
                    if self_msum[5][j] != other_msum[5][j]:
                        return False
                if len(self_msum[6]) != len(other_msum[6]):
                    return False
                for j in range(len(self_msum[6])):
                    if self_msum[6][j] != other_msum[6][j]:
                        return False
                if len(self_msum[7]) != len(other_msum[7]):
                    return False
                for j in range(len(self_msum[7])):
                    if self_msum[7][j] != other_msum[7][j]:
                        return False
            return True
        else:
            return False

    def __neq__(self, other):
        if isinstance(other, str):
            return other != self.name
        return not self == other

    def __str__(self):
        return self.name

    def __hash__(self):
        return self._id

    # endregion
