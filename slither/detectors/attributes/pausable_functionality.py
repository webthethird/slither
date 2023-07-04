"""
Module detecting unimplemented interfaces

Collect all the interfaces
Check for contracts which implement all interface functions but do not explicitly derive from those interfaces.
"""
from typing import List
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.core.declarations.contract import Contract
from slither.core.declarations.function import Function
from slither.core.variables import (
    Variable,
    StateVariable
)
from slither.utils.output import Output
from slither.core.cfg.node import NodeType
from slither.core.expressions import (
    CallExpression,
    BinaryOperation,
    BinaryOperationType,
    UnaryOperation,
    UnaryOperationType,
    AssignmentOperation,
    TupleExpression,
    Identifier
)
from slither.core.solidity_types import ElementaryType
from slither.analyses.data_dependency import data_dependency


class PausableToken(AbstractDetector):
    """
    Pausable token functionality detector
    """

    ARGUMENT = "pausable-token"
    HELP = "Pausable Token Functionality"
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#pausable-token"
    WIKI_TITLE = "Pausable Token Functionality"
    WIKI_DESCRIPTION = "Detect pausable token functionality."

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract PausableToken is ERC20 {
    bool paused;
    
    function transfer(address to, uint256 amount) external override{
        require(!paused, "Token function is paused");
        super.transfer(to, amount);
    }
    
    function setPaused(bool _pause) external {
        paused = _pause;
    }
}
```
"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Make sure users are clear about how and when functionality can be paused."

    def _detect_toggle_function(self, c: Contract, f: Function, var: Variable, bang: bool) -> List[Output]:
        results = []
        setters = c.get_functions_writing_to_variable(var)
        setters = [
            setter for setter in setters
            if not setter.is_constructor and not setter.is_constructor_variables
        ]
        dependencies = data_dependency.get_dependencies(var, c)

        if any(dep in setter.parameters for dep in dependencies for setter in
               setters):
            # Found a toggle function
            info: DETECTOR_INFO = [
                "Functionality of token function ",
                f,
                " can be paused by the function ",
                next(setter for setter in setters
                     if any(dep in setter.parameters for dep in dependencies)),
                "\n"
            ]
            res = self.generate_result(info)
            results.append(res)
        return results

    def _detect_on_off_functions(self, c: Contract, f: Function, var: Variable, bang: bool) -> List[Output]:
        results = []
        setters = c.get_functions_writing_to_variable(var)
        setters = [
            setter for setter in setters
            if not setter.is_constructor and not setter.is_constructor_variables
        ]
        pauser = None
        unpauser = None
        for setter in setters:
            if setter.is_constructor or setter.is_constructor_variables:
                continue
            for n in setter.all_nodes():
                exp = n.expression
                if (
                        isinstance(exp, AssignmentOperation)
                        and isinstance(exp.expression_left, Identifier)
                        and exp.expression_left.value == var
                ):
                    right = exp.expression_right
                    if str(right) == "true":
                        if bang:
                            pauser = setter
                        else:
                            unpauser = setter
                    elif str(right) == "false":
                        if bang:
                            unpauser = setter
                        else:
                            pauser = setter
        if pauser is not None and unpauser is not None:
            info: DETECTOR_INFO = [
                "Functionality of token function ",
                f,
                " can be paused by the function ",
                pauser,
                " and can be unpaused by the function ",
                unpauser,
                "\n"
            ]
            res = self.generate_result(info)
            results.append(res)
        return results

    def _detect(self) -> List[Output]:
        """Detect pausable token functionality"""
        results = []
        for c in self.contracts:
            if c.is_token:  # Only concerned with tokens
                transfer = c.get_function_from_signature("transfer(address,uint256)")
                transfer_from = c.get_function_from_signature("transferFrom(address,address,uint256)")
                transfer_funcs = [func for func in [transfer, transfer_from] if func is not None]
                for t in transfer_funcs:    # Only concerned with transfer functions
                    for node in t.all_nodes():
                        if node.type == NodeType.EXPRESSION:
                            exp = node.expression
                            if isinstance(exp, CallExpression) and "require" in str(exp.called):
                                # Find require statements that check some changeable boolean condition
                                condition_exp = exp.arguments[0]
                                bang = False
                                if (
                                    isinstance(condition_exp, UnaryOperation)
                                    and condition_exp.type == UnaryOperationType.BANG
                                ):
                                    condition_exp = condition_exp.expression
                                    bang = True
                                if (
                                    isinstance(condition_exp, Identifier)
                                    and isinstance(condition_exp.value.type, ElementaryType)
                                    and condition_exp.value.type.name == "bool"
                                ):
                                    # If condition is a boolean variable, check if its value can be set to true or false
                                    bool_var = condition_exp.value
                                    toggle_results = self._detect_toggle_function(c, t, bool_var, bang)
                                    if len(toggle_results) > 0:
                                        results.extend(toggle_results)
                                    else:
                                        # No toggle function, look for separate pause and unpause functions
                                        on_off_results = self._detect_on_off_functions(c, t, bool_var, bang)
                                        if len(on_off_results) > 0:
                                            results.extend(on_off_results)
                                # Condition expression may be a BinaryOperation, which could be nested
                                conditions = [condition_exp]
                                while len(conditions) > 0:
                                    condition_exp = conditions.pop()
                                    if isinstance(condition_exp, TupleExpression):
                                        conditions.extend(condition_exp.expressions)
                                    if isinstance(condition_exp, BinaryOperation):
                                        # Look for a comparison involving some state variable
                                        exp_left = condition_exp.expression_left
                                        exp_right = condition_exp.expression_right
                                        if condition_exp.type in [
                                            BinaryOperationType.OROR,
                                            BinaryOperationType.ANDAND
                                        ]:
                                            conditions.extend([exp_left, exp_right])
                                        elif condition_exp.type in [
                                            BinaryOperationType.GREATER,
                                            BinaryOperationType.GREATER_EQUAL,
                                            BinaryOperationType.LESS,
                                            BinaryOperationType.LESS_EQUAL,
                                            BinaryOperationType.EQUAL,
                                            BinaryOperationType.NOT_EQUAL
                                        ]:
                                            # Not interested in require statements that check the validity of a param
                                            params_compared = [
                                                exp for exp in [exp_left, exp_right]
                                                if any(p.name in str(exp) for p in t.parameters)
                                            ]
                                            if len(params_compared) > 0:
                                                continue

                                            state_vars = [
                                                exp.value for exp in [exp_left, exp_right]
                                                if isinstance(exp, Identifier)
                                                and isinstance(exp.value, StateVariable)
                                            ]
                                            for var in state_vars:
                                                toggle_results = self._detect_toggle_function(c, t, var, bang)
                                                if len(toggle_results) > 0:
                                                    results.extend(toggle_results)
                                                else:
                                                    # No toggle function, look for separate pause and unpause functions
                                                    on_off_results = self._detect_on_off_functions(c, t, var, bang)
                                                    if len(on_off_results) > 0:
                                                        results.extend(on_off_results)

        return results
