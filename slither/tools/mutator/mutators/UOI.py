from typing import Dict
from collections import defaultdict

from slither.slithir.operations.unary import UnaryOperationType
from slither.slithir.variables import Constant
from slither.core.variables.local_variable import LocalVariable
from slither.formatters.utils.patches import create_patch
from slither.tools.mutator.mutators.abstract_mutator import AbstractMutator, FaultNature, FaultClass


unary_operators = [
    UnaryOperationType.PLUSPLUS_PRE,
    UnaryOperationType.MINUSMINUS_PRE,
    UnaryOperationType.PLUSPLUS_POST,
    UnaryOperationType.MINUSMINUS_POST,
    UnaryOperationType.MINUS_PRE,
]


class UOI(AbstractMutator):  # pylint: disable=too-few-public-methods
    NAME = "UOI"
    HELP = "Unary operator insertion"
    FAULTCLASS = FaultClass.Checking
    FAULTNATURE = FaultNature.Missing

    def _mutate(self) -> Dict:

        result: Dict = {"patches": defaultdict(list)}

        for contract in self.slither.contracts:
            # Retrieve the file
            in_file = contract.source_mapping.filename.absolute
            result["patches"][in_file] = []
            # Retrieve the source code
            in_file_str = contract.compilation_unit.core.source_code[in_file]

            for function in contract.functions_and_modifiers_declared:

                for node in function.nodes:
                    for ir in node.irs:
                        for operand in ir.read:
                            if isinstance(operand, (LocalVariable, Constant)):
                                for op in unary_operators:

                                    # Get the string
                                    start = node.source_mapping.start
                                    stop = start + node.source_mapping.length
                                    old_str = in_file_str[start:stop]

                                    # Replace the expression with true
                                    new_str = old_str.replace(str(operand), f"{str(op)}{operand}")
                                    patch = create_patch(start, stop, old_str, new_str)
                                    result["patches"][in_file].append(patch)

        return result
