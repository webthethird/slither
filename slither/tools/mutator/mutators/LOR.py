from typing import Dict
from collections import defaultdict
from slither.slithir.operations import Binary, BinaryType
from slither.formatters.utils.patches import create_patch
from slither.tools.mutator.mutators.abstract_mutator import AbstractMutator, FaultNature, FaultClass


logical_operators = [
    BinaryType.OROR,
    BinaryType.ANDAND,
]


class LOR(AbstractMutator):  # pylint: disable=too-few-public-methods
    NAME = "LOR"
    HELP = "Logical operator replacement"
    FAULTCLASS = FaultClass.Checking
    FAULTNATURE = FaultNature.Missing

    def _mutate(self) -> Dict:

        result: Dict = {"patches": defaultdict(list)}

        for contract in self.slither.contracts:
            # Retrieve the file
            in_file = contract.source_mapping.filename.absolute
            # Retrieve the source code
            in_file_str = contract.compilation_unit.core.source_code[in_file]
            result["patches"][in_file] = []
            for function in contract.functions_and_modifiers_declared:

                for node in function.nodes:
                    for ir in node.irs:
                        if isinstance(ir, Binary) and ir.type in logical_operators:
                            alternative_ops = logical_operators[:]
                            alternative_ops.remove(ir.type)

                            for op in alternative_ops:

                                # Get the string
                                start = node.source_mapping.start
                                stop = start + node.source_mapping.length
                                old_str = in_file_str[start:stop]

                                # Replace the expression with true
                                new_str = f"{ir.variable_left} {op.value} {ir.variable_right}"

                                p = create_patch(start, stop, old_str, new_str)
                                print(p)
                                result["patches"][in_file].append(p)

        return result
