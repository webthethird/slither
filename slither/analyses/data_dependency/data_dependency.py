"""
    Compute the data depenency between all the SSA variables
"""
from collections import defaultdict
from typing import Union, Set, Dict, TYPE_CHECKING

from slither.core.declarations import (
    Contract,
    Enum,
    Function,
    FunctionContract,
    SolidityFunction,
    SolidityVariable,
    SolidityVariableComposed,
    Structure,
)
from slither.core.declarations.solidity_import_placeholder import SolidityImportPlaceHolder
from slither.core.variables.variable import Variable
from slither.slithir.operations import Index, OperationWithLValue, InternalCall
from slither.slithir.variables import (
    Constant,
    LocalIRVariable,
    ReferenceVariable,
    ReferenceVariableSSA,
    StateIRVariable,
    TemporaryVariable,
    TemporaryVariableSSA,
    TupleVariableSSA,
)
from slither.core.solidity_types.type import Type
from slither.core.solidity_types import (
    UserDefinedType
)
from slither.core.expressions import (
    CallExpression,
    MemberAccess,
    Identifier
)

if TYPE_CHECKING:
    from slither.core.compilation_unit import SlitherCompilationUnit


###################################################################################
###################################################################################
# region User APIs
###################################################################################
###################################################################################


def is_dependent(
    variable: Variable,
    source: Variable,
    context: Union[Contract, Function],
    only_unprotected: bool = False,
) -> bool:
    """
    Args:
        variable (Variable)
        source (Variable)
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    """
    assert isinstance(context, (Contract, Function))
    if isinstance(variable, Constant):
        return False
    if variable == source:
        return True
    context_dict = context.context

    if only_unprotected:
        return (
            variable in context_dict[KEY_NON_SSA_UNPROTECTED]
            and source in context_dict[KEY_NON_SSA_UNPROTECTED][variable]
        )
    return variable in context_dict[KEY_NON_SSA] and source in context_dict[KEY_NON_SSA][variable]


def is_dependent_ssa(
    variable: Variable,
    source: Variable,
    context: Union[Contract, Function],
    only_unprotected: bool = False,
) -> bool:
    """
    Args:
        variable (Variable)
        taint (Variable)
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    """
    assert isinstance(context, (Contract, Function))
    context_dict = context.context
    if isinstance(variable, Constant):
        return False
    if variable == source:
        return True
    if only_unprotected:
        return (
            variable in context_dict[KEY_SSA_UNPROTECTED]
            and source in context_dict[KEY_SSA_UNPROTECTED][variable]
        )
    return variable in context_dict[KEY_SSA] and source in context_dict[KEY_SSA][variable]


GENERIC_TAINT = {
    SolidityVariableComposed("msg.sender"),
    SolidityVariableComposed("msg.value"),
    SolidityVariableComposed("msg.data"),
    SolidityVariableComposed("tx.origin"),
}


def is_tainted(variable, context, only_unprotected=False, ignore_generic_taint=False):
    """
        Args:
        variable
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if isinstance(variable, Constant):
        return False
    compilation_unit = context.compilation_unit
    taints = compilation_unit.context[KEY_INPUT]
    if not ignore_generic_taint:
        taints |= GENERIC_TAINT
    return variable in taints or any(
        is_dependent(variable, t, context, only_unprotected) for t in taints
    )


def is_tainted_ssa(variable, context, only_unprotected=False, ignore_generic_taint=False):
    """
    Args:
        variable
        context (Contract|Function)
        only_unprotected (bool): True only unprotected function are considered
    Returns:
        bool
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if isinstance(variable, Constant):
        return False
    compilation_unit = context.compilation_unit
    taints = compilation_unit.context[KEY_INPUT_SSA]
    if not ignore_generic_taint:
        taints |= GENERIC_TAINT
    return variable in taints or any(
        is_dependent_ssa(variable, t, context, only_unprotected) for t in taints
    )


def get_dependencies(
    variable: Variable,
    context: Union[Contract, Function],
    only_unprotected: bool = False,
) -> Set[Variable]:
    """
    Return the variables for which `variable` depends on.

    :param variable: The target
    :param context: Either a function (interprocedural) or a contract (inter transactional)
    :param only_unprotected: True if consider only protected functions
    :return: set(Variable)
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        return context.context[KEY_NON_SSA_UNPROTECTED].get(variable, set())
    return context.context[KEY_NON_SSA].get(variable, set())


def get_dependencies_recursive(
    variable: Variable,
    context: Union[Contract, Function],
    only_unprotected: bool = False,
) -> Set[Variable]:
    """
        Return the variables for which `variable` depends on, including those from other contexts,
        i.e., by following function calls and getting the dependencies for the return variables.

        :param variable: The target
        :param context: Either a function (interprocedural) or a contract (inter transactional)
        :param only_unprotected: True if consider only protected functions
        :return: set(Variable)
        """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        key = KEY_NON_SSA_UNPROTECTED
    else:
        key = KEY_NON_SSA
    """
    explored and to_explore are lists of Variable objects, including temporary variables.
    """
    explored = []
    to_explore = list(context.context[key].get(variable, set()))
    while to_explore:
        var: Variable = to_explore[0]
        to_explore = to_explore[1:]
        if var in explored or isinstance(var, SolidityVariable):
            continue
        print(f"Exploring {var}")
        explored.append(var)

        """
        Thanks to a small modification in /visitors/slithir/expression_to_slithir, now all
        TemporaryVariable objects representing the result of an Expression (for example, 
        a CallExpression) will have that expression stored in TemporaryVariable.expression.
        Therefore, we can use these to find function calls that lead to other dependencies.
        """
        if var.expression is not None:
            exp = var.expression
            print(f"Expression: {exp}")
            """ For now, we are only interested in tracing CallExpressions """
            if isinstance(exp, CallExpression):
                called = exp.called
                if isinstance(called, Identifier):
                    """ Indicates a simple function call within the current context """
                    call_val = called.value
                elif isinstance(called, MemberAccess) and isinstance(called.expression, Identifier):
                    """ Indicates a function call to another contract """
                    value: Variable = called.expression.value
                    c_type = value.type
                    if isinstance(c_type, UserDefinedType):
                        c_type = c_type.type
                    if isinstance(c_type, Contract):
                        if c_type.is_interface:
                            for c in context.compilation_unit.contracts:
                                if c_type in c.inheritance:
                                    c_type = c
                        print(f"MemberAccess.expression.value = {value}, type = {c_type}")
                        call_val = c_type.get_function_from_name(called.member_name)
                        print(f"call_val: {call_val}")
                else:
                    continue
                if isinstance(call_val, FunctionContract) and len(call_val.returns) > 0:
                    returns = call_val.returns
                    if call_val.return_nodes() is not None and len(call_val.return_nodes()) > 0:
                        for ret_node in call_val.return_nodes():
                            ret_exp = ret_node.expression

                    for ret in call_val.returns:
                        to_explore.append(ret)
                        if isinstance(context, Contract):
                            new_context = call_val.contract
                        else:
                            new_context = call_val
                        to_explore += [
                            v for v in list(new_context.context[key].get(ret, set()))
                            if v not in to_explore and v not in explored
                        ]
    return set(explored)


def get_all_dependencies(
    context: Union[Contract, Function], only_unprotected: bool = False
) -> Dict[Variable, Set[Variable]]:
    """
    Return the dictionary of dependencies.

    :param context: Either a function (interprocedural) or a contract (inter transactional)
    :param only_unprotected: True if consider only protected functions
    :return: Dict(Variable, set(Variable))
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        return context.context[KEY_NON_SSA_UNPROTECTED]
    return context.context[KEY_NON_SSA]


def get_dependencies_ssa(
    variable: Variable,
    context: Union[Contract, Function],
    only_unprotected: bool = False,
) -> Set[Variable]:
    """
    Return the variables for which `variable` depends on (SSA version).

    :param variable: The target (must be SSA variable)
    :param context: Either a function (interprocedural) or a contract (inter transactional)
    :param only_unprotected: True if consider only protected functions
    :return: set(Variable)
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        return context.context[KEY_SSA_UNPROTECTED].get(variable, set())
    return context.context[KEY_SSA].get(variable, set())


def get_all_dependencies_ssa(
    context: Union[Contract, Function], only_unprotected: bool = False
) -> Dict[Variable, Set[Variable]]:
    """
    Return the dictionary of dependencies.

    :param context: Either a function (interprocedural) or a contract (inter transactional)
    :param only_unprotected: True if consider only protected functions
    :return: Dict(Variable, set(Variable))
    """
    assert isinstance(context, (Contract, Function))
    assert isinstance(only_unprotected, bool)
    if only_unprotected:
        return context.context[KEY_SSA_UNPROTECTED]
    return context.context[KEY_SSA]


# endregion
###################################################################################
###################################################################################
# region Module constants
###################################################################################
###################################################################################

KEY_SSA = "DATA_DEPENDENCY_SSA"
KEY_NON_SSA = "DATA_DEPENDENCY"

# Only for unprotected functions
KEY_SSA_UNPROTECTED = "DATA_DEPENDENCY_SSA_UNPROTECTED"
KEY_NON_SSA_UNPROTECTED = "DATA_DEPENDENCY_UNPROTECTED"

KEY_INPUT = "DATA_DEPENDENCY_INPUT"
KEY_INPUT_SSA = "DATA_DEPENDENCY_INPUT_SSA"


# endregion
###################################################################################
###################################################################################
# region Debug
###################################################################################
###################################################################################


def pprint_dependency(context):
    print("#### SSA ####")
    context = context.context
    for k, values in context[KEY_SSA].items():
        print("{} ({}):".format(k, id(k)))
        for v in values:
            print("\t- {}".format(v))

    print("#### NON SSA ####")
    for k, values in context[KEY_NON_SSA].items():
        print("{} ({}):".format(k, hex(id(k))))
        for v in values:
            print("\t- {} ({})".format(v, hex(id(v))))


# endregion
###################################################################################
###################################################################################
# region Analyses
###################################################################################
###################################################################################


def compute_dependency(compilation_unit: "SlitherCompilationUnit"):
    compilation_unit.context[KEY_INPUT] = set()
    compilation_unit.context[KEY_INPUT_SSA] = set()

    for contract in compilation_unit.contracts:
        compute_dependency_contract(contract, compilation_unit)


def compute_dependency_contract(contract, compilation_unit: "SlitherCompilationUnit"):
    if KEY_SSA in contract.context:
        return

    contract.context[KEY_SSA] = dict()
    contract.context[KEY_SSA_UNPROTECTED] = dict()

    for function in contract.functions + contract.modifiers:
        compute_dependency_function(function)

        propagate_function(contract, function, KEY_SSA, KEY_NON_SSA)
        propagate_function(contract, function, KEY_SSA_UNPROTECTED, KEY_NON_SSA_UNPROTECTED)

        # pylint: disable=expression-not-assigned
        if function.visibility in ["public", "external"]:
            [compilation_unit.context[KEY_INPUT].add(p) for p in function.parameters]
            [compilation_unit.context[KEY_INPUT_SSA].add(p) for p in function.parameters_ssa]

    propagate_contract(contract, KEY_SSA, KEY_NON_SSA)
    propagate_contract(contract, KEY_SSA_UNPROTECTED, KEY_NON_SSA_UNPROTECTED)


def propagate_function(contract, function, context_key, context_key_non_ssa):
    transitive_close_dependencies(function, context_key, context_key_non_ssa)
    # Propage data dependency
    data_depencencies = function.context[context_key]
    for (key, values) in data_depencencies.items():
        if not key in contract.context[context_key]:
            contract.context[context_key][key] = set(values)
        else:
            contract.context[context_key][key].union(values)


def transitive_close_dependencies(context, context_key, context_key_non_ssa):
    # transitive closure
    changed = True
    keys = context.context[context_key].keys()
    while changed:
        changed = False
        to_add = defaultdict(set)
        [  # pylint: disable=expression-not-assigned
            [
                to_add[key].update(context.context[context_key][item] - {key} - items)
                for item in items & keys
            ]
            for key, items in context.context[context_key].items()
        ]
        for k, v in to_add.items():
            # Because we dont have any check on the update operation
            # We might update an empty set with an empty set
            if v:
                changed = True
                context.context[context_key][k] |= v
    context.context[context_key_non_ssa] = convert_to_non_ssa(context.context[context_key])


def propagate_contract(contract, context_key, context_key_non_ssa):
    transitive_close_dependencies(contract, context_key, context_key_non_ssa)


def add_dependency(lvalue, function, ir, is_protected):
    if not lvalue in function.context[KEY_SSA]:
        function.context[KEY_SSA][lvalue] = set()
        if not is_protected:
            function.context[KEY_SSA_UNPROTECTED][lvalue] = set()
    if isinstance(ir, Index):
        read = [ir.variable_left]
    elif isinstance(ir, InternalCall):
        read = ir.function.return_values_ssa
    else:
        read = ir.read
    # pylint: disable=expression-not-assigned
    [function.context[KEY_SSA][lvalue].add(v) for v in read if not isinstance(v, Constant)]
    if not is_protected:
        [
            function.context[KEY_SSA_UNPROTECTED][lvalue].add(v)
            for v in read
            if not isinstance(v, Constant)
        ]


def compute_dependency_function(function):
    if KEY_SSA in function.context:
        return

    function.context[KEY_SSA] = dict()
    function.context[KEY_SSA_UNPROTECTED] = dict()

    is_protected = function.is_protected()
    for node in function.nodes:
        for ir in node.irs_ssa:
            if isinstance(ir, OperationWithLValue) and ir.lvalue:
                if isinstance(ir.lvalue, LocalIRVariable) and ir.lvalue.is_storage:
                    continue
                if isinstance(ir.lvalue, ReferenceVariable):
                    lvalue = ir.lvalue.points_to
                    if lvalue:
                        add_dependency(lvalue, function, ir, is_protected)
                add_dependency(ir.lvalue, function, ir, is_protected)

    function.context[KEY_NON_SSA] = convert_to_non_ssa(function.context[KEY_SSA])
    function.context[KEY_NON_SSA_UNPROTECTED] = convert_to_non_ssa(
        function.context[KEY_SSA_UNPROTECTED]
    )


def convert_variable_to_non_ssa(v):
    if isinstance(
        v,
        (
            LocalIRVariable,
            StateIRVariable,
            TemporaryVariableSSA,
            ReferenceVariableSSA,
            TupleVariableSSA,
        ),
    ):
        return v.non_ssa_version
    assert isinstance(
        v,
        (
            Constant,
            SolidityVariable,
            Contract,
            Enum,
            SolidityFunction,
            Structure,
            Function,
            Type,
            SolidityImportPlaceHolder,
        ),
    )
    return v


def convert_to_non_ssa(data_depencies):
    # Need to create new set() as its changed during iteration
    ret = dict()
    for (k, values) in data_depencies.items():
        var = convert_variable_to_non_ssa(k)
        if not var in ret:
            ret[var] = set()
        ret[var] = ret[var].union({convert_variable_to_non_ssa(v) for v in values})

    return ret
