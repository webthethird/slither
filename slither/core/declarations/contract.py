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
        from slither.core.expressions.expression_typed import ExpressionTyped
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.assignment_operation import AssignmentOperation
        from slither.core.expressions.member_access import MemberAccess
        from slither.core.expressions.identifier import Identifier

        print_debug = True
        if print_debug:
            print("Begin " + self.name + ".is_upgradeable_proxy")

        if self._is_upgradeable_proxy is None:
            self._is_upgradeable_proxy = False
            if print_debug:
                ("\nChecking contract: " + self.name)
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
                self._proxy_impl_setter = self.find_setter_in_contract(self, self._delegates_to, print_debug)
                if self._proxy_impl_setter is not None:
                    if print_debug:
                        print("\nImplementation set by function: " + self._proxy_impl_setter.name + " in contract: "
                              + self.name)
                    self._is_upgradeable_proxy = True
                elif print_debug:
                    print("\nCould not find implementation setter in " + self.name)
                
                # then find getter
                if print_debug:
                    print("Looking for getter\n")
                self._proxy_impl_getter = self.find_getter_in_contract(self, self._delegates_to, print_debug)
                
                # if both setter and getter can be found, then return true
                # Otherwise, at lest the getter's return is non-constant
                if self._proxy_impl_getter is not None:
                    if self._proxy_impl_setter is not None:
                        self._is_upgradeable_proxy = True
                        return self._is_upgradeable_proxy
                    else:
                        return self.getter_return_is_non_constant(print_debug)


                    # TODO: Generalize this method and move this logic to an upgradeability check
                    """
                    All of the commented out code below is for cross-contract analysis,
                    i.e. to discover calls to an implementation getter that is located in another contract
                    """
                    # exp = None
                    # for node in impl_getter.all_nodes():
                    #     if print_debug:
                    #         print(node.type)
                    #     # if node.expression is not None:
                    #     if node.type == NodeType.RETURN:
                    #         exp = node.expression
                    #         if print_debug:
                    #             print(exp)
                    #         if isinstance(exp, CallExpression):
                    #             if print_debug:
                    #                 print("This return node is a CallExpression")
                    #             if isinstance(exp.called, MemberAccess):
                    #                 if print_debug:
                    #                     print("The CallExpression is for MemberAccess")
                    #                 exp = exp.called
                    #                 break
                    #         elif isinstance(node.expression, Identifier):
                    #             if print_debug:
                    #                 print("This return node is a variable Identifier")
                    #         elif node.expression.type is not None:
                    #             if print_debug:
                    #                 print(node.expression.type)
                    #     elif node.type == NodeType.VARIABLE:
                    #         if print_debug:
                    #             print(node.variable_declaration.expression)
                    # if isinstance(exp, MemberAccess):  # Getter calls function of another contract in return expression
                    #     call_exp = exp.expression
                    #     call_function = exp.member_name
                    #     call_contract = None
                    #     if isinstance(call_exp, TypeConversion):
                    #         if print_debug:
                    #             print("The return node calls a function from a contract of type " + str(call_exp.type))
                    #         call_type = call_exp.type
                    #     if call_type is not None:
                    #         call_contract = self.compilation_unit.get_contract_from_name(str(call_type))
                    #         if call_contract is not None:
                    #             if print_debug:
                    #                 print("\nFound contract called by proxy: " + call_contract.name)
                    #             interface = None
                    #             if call_contract.is_interface:
                    #                 interface = call_contract
                    #                 call_contract = None
                    #                 if print_debug:
                    #                     print("It's an interface\nLooking for a contract that implements the interface "
                    #                           + interface.name)
                    #                 for c in self.compilation_unit.contracts:
                    #                     if interface in c.inheritance:
                    #                         if print_debug:
                    #                             print(c.name + " inherits the interface " + interface.name)
                    #                         call_contract = c
                    #                         break
                    #                 if call_contract is None:
                    #                     if print_debug:
                    #                         print("Could not find a contract that inherits " + interface.name + "\n"
                    #                               + "Looking for a contract with " + call_function)
                    #                     for c in self.compilation_unit.contracts:
                    #                         has_called_func = False
                    #                         if c == interface:
                    #                             continue
                    #                         for f in interface.functions_signatures:
                    #                             if exp.member_name not in f:
                    #                                 continue
                    #                             if f in c.functions_signatures:
                    #                                 if print_debug:
                    #                                     print(c.name + " has function " + f + " from interface")
                    #                                 has_called_func = True
                    #                                 break
                    #                         if has_called_func:
                    #                             print(c.name + " contains the implementation getter")
                    #                             call_contract = c
                    #                             break
                    #                 if call_contract is None:
                    #                     if print_debug:
                    #                         print("Could not find a contract that implements " + exp.member_name
                    #                               + " from " + interface.name + ":")
                    #                 else:
                    #                     if print_debug:
                    #                         print("Looking for implementation setter in " + call_contract.name)
                    #                     self._proxy_impl_setter = self.find_setter_in_contract(call_contract,
                    #                                                                            self._delegates_to)
                    #                     if self._proxy_impl_setter is not None:
                    #                         if print_debug:
                    #                             print("\nImplementation set by function: "
                    #                                   + self._proxy_impl_setter.name + " in contract: "
                    #                                   + call_contract.name)
                    #                         self._is_upgradeable_proxy = True
                    #                         return self._is_upgradeable_proxy
                    #             if call_contract is not None and not call_contract.is_interface:
                    #                 contains_getter = False
                    #                 contains_setter = False
                    #                 implementation = None
                    #                 for f in call_contract.functions:
                    #                     if f.name == exp.member_name:
                    #                         for v in f.returns:
                    #                             if str(v.type) == "address":
                    #                                 if print_debug:
                    #                                     print("Found getter " + f.name + " in " + call_contract.name)
                    #                                 contains_getter = True
                    #                                 call_function = f
                    #                                 break
                    #                         if contains_getter:
                    #                             for v in f.variables_read:
                    #                                 if isinstance(v, StateVariable):
                    #                                     implementation = v
                    #                                     break
                    #                             break
                    #                 if contains_getter:
                    #                     if print_debug:
                    #                         print("Looking for implementation setter in " + call_contract.name)
                    #                     self._proxy_impl_setter = self.find_setter_in_contract(call_contract,
                    #                                                                            self._delegates_to)
                    #                     if self._proxy_impl_setter is not None:
                    #                         if print_debug:
                    #                             print("Found implementation setter ")
                    #                         self._is_upgradeable_proxy = True
                    #                         return self._is_upgradeable_proxy
                    #         else:
                    #             if print_debug:
                    #                 print("Could not find a contract called " + str(call_type) + " in compilation unit")
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

        if self._is_proxy is None:
            self._is_proxy = False

            if self.fallback_function is None:
                print("\nEnd " + self.name + ".is_proxy\n")
                return self._is_proxy

            self._delegates_to = None

            if print_debug:
                print("\nBegin " + self.name + ".is_proxy\n")
            for node in self.fallback_function.all_nodes():
                if print_debug:
                    print(str(node.type))

                # first try to find a delegetecall in non-assembly code region
                self._is_proxy, self._delegates_to = self.find_delegatecall(node, print_debug)
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
                        self._is_proxy, self._delegates_to = self.find_delegatecall_in_asm(node.inline_asm,
                                                                                                node.function)
                        if self._is_proxy and self._delegates_to is not None:
                            break
                elif node.type == NodeType.EXPRESSION:
                    self._is_proxy, self._delegates_to = self.handle_assembly_in_version_0_6_0_and_above(node, print_debug)


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
        from slither.core.cfg.node import NodeType
        from slither.core.variables.variable import Variable
        from slither.core.variables.state_variable import StateVariable
        from slither.core.variables.local_variable import LocalVariable
        from slither.core.expressions.call_expression import CallExpression
        from slither.core.expressions.identifier import Identifier
        from slither.core.solidity_types.elementary_type import ElementaryType

        print_debug = True
        is_proxy = False
        delegates_to: Variable = None

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
                        if print_debug:
                            print("\nFound delegatecall in YulFunctionCall\n")
                        is_proxy = True
                        args = statement["arguments"]
                        dest = args[1]
                        if dest["nodeType"] == "YulIdentifier":
                            for v in parent_func.variables_read:
                                if isinstance(v, Variable):
                                    if print_debug:
                                        print(str(v.expression))
                                    if v.name == dest["name"]:
                                        delegates_to = v
                                        break
                        break
        else:
            # TODO: break out corner cases to clean this mess up
            asm_split = inline_asm.split("\n")
            dest = None
            for asm in asm_split:
                if print_debug:
                    print(asm)
                if "delegatecall" in asm:
                    is_proxy = True   # Now look for the target of this delegatecall
                    params = asm.split("delegatecall(")[1].split(", ")
                    dest: str = params[1]   # Target should be 2nd parameter, but 1st param might have 2 params
                    if dest.endswith(")"):  # i.e. delegatecall(sub(gas, 10000), _dst, free_ptr, calldatasize, 0, 0)
                        dest = params[2]
                    if dest.startswith("sload("):
                        dest = dest.replace(")", "(").split("(")[1]
                    if print_debug:
                        print("\nFound delegatecall in inline asm")
                        print("Destination param is called '" + dest + "'\nChecking variables read\n")
                        print("Current function: " + parent_func.name)
                    for v in parent_func.variables_read:
                        if print_debug:
                            print(str(v))
                        if v.name == dest:
                            if isinstance(v, StateVariable):
                                delegates_to = v
                                if print_debug:
                                    print("Destination variable is " + str(v))
                                    if delegates_to.type is not None:
                                        print("which has type: " + str(v.type))
                                break
                            elif isinstance(v, LocalVariable):
                                print(v.expression)
                    if delegates_to is None:
                        for idx, p in enumerate(parent_func.parameters):
                            """
                            Handles the common case in which fallback calls _delegate(_implementation()),
                            and where the signature for _delegate is _delegate(address implementation)
                            i.e. the function parameter 'implementation' w/o underscore is passed to delegatecall, but 
                            that variable can't be found anywhere else and there's no other variable to trace it back to
                            ex: /tests/proxies/App.sol
                            """
                            if p.name == dest and str(p.type) == "address":
                                if print_debug:
                                    print("Found " + dest + ": it is a parameter of the function " + parent_func.name)
                                for n in self.fallback_function.all_nodes():
                                    if n.type == NodeType.EXPRESSION:
                                        exp = n.expression
                                        if isinstance(exp, CallExpression) and str(exp.called) == parent_func.name:
                                            arg = exp.arguments[idx]
                                            print(parent_func.name + " is passed in the argument " + str(arg))
                                            if isinstance(arg, CallExpression):
                                                called = arg.called
                                                if isinstance(called, Identifier):
                                                    val = called.value
                                                    if isinstance(val, Function) and len(val.returns) > 0:
                                                        delegates_to = val.returns[0]
                                                        if delegates_to.name == "":
                                                            delegates_to.name = dest
                                                        self._proxy_impl_getter = val
                                                        print("Found getter function which is the source of " + dest)
                                                        break
                                break
                        """
                        Do not rely on looking for dest in function names, which may be arbitrary.
                        The code above accomplishes the same, but does not manipulate any strings before comparing.
                        
                        i.e. Rather than searching all of the functions and checking if dest in f.name.lower(),
                             we instead follow the chain of CallExpressions back to find the source of the 
                             address parameter used in the delegatecall expression. This has the added benefit that 
                             this also reveals the implementation getter, self._proxy_impl_getter, ahead of time
                        """
                        # for f in self.functions:
                        #     if dest in f.name.lower():
                        #         if print_debug:
                        #             print("Found '" + dest + "' in function named " + f.name)
                        #         if len(f.returns) > 0:
                        #             for ret in f.returns:
                        #                 if str(ret.type) == "address":
                        #                     if print_debug:
                        #                         print("Which returns address " + str(ret))
                        #                     delegates_to = ret
                        #                     if ret.name == "":
                        #                         delegates_to.name = f.name
                        #                     break
                        #             if delegates_to is not None:
                        #                 break
                    break
            if is_proxy and delegates_to is None and dest is not None:
                """
                This means we extracted the name of the address variable passed as the second parameter
                to delegatecall, but could not find a state variable or getter function that matches it.
                ex: /tests/proxies/APMRegistry.sol, in which we find '_dst' but want 'target':
                function () payable public {
                    address target = getCode();
                    delegatedFwd(target, msg.data);
                }
                function delegatedFwd(address _dst, bytes _calldata) internal {
                    assembly {
                        let result := delegatecall(sub(gas, 10000), _dst, add(_calldata, 0x20), mload(_calldata), 0, 0)
                        ...
                    }
                }
                """
                if print_debug:
                    print("Could not find state variable or getter function for " + dest)
                for node in self.fallback_function.all_nodes():
                    print(node.type)
                    if node.type == NodeType.VARIABLE:
                        print(node.expression)
                        if node.variable_declaration is not None and node.variable_declaration.name == dest:
                            print("Found variable declaration for " + dest + "!")
                            delegates_to = node.variable_declaration
                    elif node.type == NodeType.EXPRESSION:
                        exp = node.expression
                        print(exp)
                        if isinstance(exp, CallExpression):
                            print(exp.called)
                            _dest = None
                            for f in self.functions:
                                if f.name == str(exp.called):
                                    print("Found the function called " + f.name)
                                    for idx, v in enumerate(f.parameters):
                                        if v.name == dest and str(v.type) == "address":
                                            print(dest + " is a parameter passed to " + f.name)
                                            _dest = idx
                                            break
                                    if _dest is not None:
                                        break
                            if _dest is not None:
                                arg = exp.arguments[_dest]
                                if isinstance(arg, Identifier) and str(arg.value.type) == "address":
                                    delegates_to = arg.value
                                    print(arg.value.expression)
                                    break
                if delegates_to is None:
                    """
                    Finally, here I am trying to handle the case where there are no variables at all in the proxy,
                    except for one defined within the assembly block itself and the slot hardcoded as seen below.
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
                    for asm in asm_split:
                        if dest in asm and "= sload(" in asm:
                            slot = asm.split("(", 1)[1].strip(")")
                            if len(slot) == 66 and slot.startswith("0x"):  # 32-bit memory address
                                delegates_to = LocalVariable()
                                delegates_to.set_type(ElementaryType("address"))
                                delegates_to.name = dest
                                delegates_to.set_location(slot)
                                break
        if print_debug:
            print("\nEnd " + self.name + ".find_delegatecall_in_asm\n")
        return is_proxy, delegates_to


    def find_delegatecall(self, node, print_debug):
        """
        Handles finding delegatecall outside of an assembly block, 
        i.e. delegate.delegatecall(msg.data)  
        ex: tests/proxies/Delegation.sol (appears to have been written to demonstrate a vulnerability) 
        """
        from slither.slithir.operations import LowLevelCall
    
        for ir in node.irs:
            if isinstance(ir, LowLevelCall):
                if print_debug:
                    print("\nFound LowLevelCall\n")
                if ir.function_name == "delegatecall":
                    if print_debug:
                        print("\nFound delegatecall in LowLevelCall\n")
                    return True, ir.destination
        return False, None



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
        from slither.core.expressions.identifier import Identifier
        is_proxy = False
        delegate_to = None

        expression = node.expression
        if print_debug:
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
                        print(dest.value.expression)
                        delegate_to = dest.value


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

        if print_debug:
            print("\nFound getter function but not setter\nChecking if getter calls any other function")
        for node in self._proxy_impl_getter.all_nodes():
            exp = node.expression
            if print_debug:
                print(str(node.type) + ": " + str(exp))
            if node.type == NodeType.EXPRESSION and isinstance(exp, AssignmentOperation):
                left = exp.expression_left
                right = exp.expression_right
                if isinstance(left, Identifier) and left.value == self._delegates_to:
                    print(right)
                    if isinstance(right, Identifier) and right.value.is_constant:
                        self._is_upgradeable_proxy = False
                        return self._is_upgradeable_proxy
                    elif isinstance(right, CallExpression):
                        print("Call Expression")
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
                # elif isinstance(exp, Identifier) and isinstance(exp.value, StateVariable)



    @staticmethod
    def find_getter_in_contract(contract: "Contract", var_to_set: Union[str, "Variable"], print_debug) -> Optional[Function]:
        from slither.core.expressions.call_expression import CallExpression
        setter = None
        
        exp = var_to_set.expression
        if exp is not None and isinstance(exp, CallExpression):
            print(exp)
            exp = exp.called
        for f in contract.functions:
            if contract._proxy_impl_getter is not None:
                if print_debug:
                    print("\n" + f.name + " appears to be the implementation getter\n")
                break
            if f.name is not None:
                if print_debug:
                    print("Checking function: " + f.name)
                if exp is not None and f.name == str(exp) and len(f.all_nodes()) > 0:
                    setter = f
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
                        if str(v.type) == "address" and str(var_to_set).strip("_") in f.name:
                            if print_debug:
                                print("\n" + f.name + " appears to be the implementation getter\n")
                            setter = f
                            break
        return setter





    @staticmethod
    def find_setter_in_contract(
            contract: "Contract",
            var_to_set: Union[str, "Variable"],
            print_debug: "bool"
    ) -> Optional[Function]:
        """
        Tries to find the setter function for a given variable.
        Static because we can use this for cross-contract implementation setters, i.e. EIP 1822 Proxy/Proxiable

        :param contract: the Contract to look in
        :param var_to_set: the Variable to look for, or at least its name as a string
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
            print("\nBegin " + contract.name + ".find_setter_in_asm\n")
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
            if not f.name == "fallback" and "constructor" not in f.name.lower() and "init" not in f.name.lower():
                for v in f.variables_written:
                    if isinstance(v, LocalVariable) and v in f.returns:
                        if print_debug:
                            print(f.name + " returns local variable: " + v.name)
                        continue
                    elif isinstance(v, StateVariable):
                        if print_debug:
                            print(f.name + " writes to state variable: " + v.name)
                            # TODO: clean up string usage if possible
                        if str(var_to_set).strip("_").lower() in v.name.strip("_").lower():
                            setter = f
                            break
                if f.contains_assembly:
                    if print_debug:
                        print(f.name + " contains assembly")
                    for node in f.all_nodes():
                        if setter is not None:
                            break
                        inline = node.inline_asm
                        if inline:
                            # TODO: need cleanup
                            if "sstore" in inline \
                                    and (str(var_to_set).strip("_").lower() in inline.strip("_").lower()
                                         or (isinstance(var_to_set, LocalVariable) and var_to_set.location in inline)):
                                setter = f
                                break
                        else:  # @webthethird: inline_asm was not set for version >= 0.6.0, though it should be now
                            for e in f.all_expressions():
                                if "sstore" in str(e) \
                                        and (str(var_to_set).strip("_").lower() in str(e).strip("_").lower()
                                             or (isinstance(var_to_set, LocalVariable) and var_to_set.location in str(
                                            e))):
                                    setter = f
                                    break
        if setter is None and "facet" in str(var_to_set):
            """
            Handle the corner case for EIP-2535 Diamond proxy
            The function diamondCut is used to add/delete/modify logic contracts (it is the setter)
            But, this function is implemented in a facet (logic) contract itself, i.e. DiamondCutFacet
            This facet is added by the constructor, using LibDiamond.diamondCut, and subsequent calls
            to diamondCut are handled by the fallback(), which delegates to the DiamondCutFacet
            ex: /tests/proxies/DiamondFactory.sol
            """
            if print_debug:
                print("\nBegin DiamondCut corner case handling\n")
            constructor = contract.constructors_declared
            for n in constructor.all_nodes():
                if n.type == NodeType.EXPRESSION:
                    exp = n.expression
                    if print_debug:
                        print(exp)
                        if isinstance(exp, ExpressionTyped):
                            print(exp.type)
                    if isinstance(exp, CallExpression):
                        print(exp.called)
                        if "diamondCut" in str(exp.called):
                            diamond_cut = exp.arguments[0]
                            if isinstance(diamond_cut, Identifier) and "DiamondCut" in str(diamond_cut.value.type):
                                idiamond_cut = contract.compilation_unit.get_contract_from_name("IDiamondCut")
                                cut_facet = idiamond_cut
                                for c in contract.compilation_unit.contracts:
                                    if c == idiamond_cut:
                                        continue
                                    if idiamond_cut in c.inheritance:
                                        cut_facet = c
                                for f in cut_facet.functions:
                                    if f.name == "diamondCut":
                                        setter = f
                                        break
            if print_debug:
                print("\nEnd DiamondCut corner case handling\n")
        if print_debug:
            print("\nEnd " + contract.name + ".find_setter_in_asm\n")
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
