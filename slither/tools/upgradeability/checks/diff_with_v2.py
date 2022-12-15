from slither.tools.upgradeability.checks.abstract_checks import (
    CheckClassification,
    AbstractCheck,
)


class DiffContractV1ContractV2(AbstractCheck):
    ARGUMENT = "diff-v1-v2"
    IMPACT = CheckClassification.INFORMATIONAL

    HELP = "Diff between v1 and v2"
    WIKI = "https://github.com/crytic/slither/wiki/Upgradeability-Checks#differences-between-v1-and-v2"
    WIKI_TITLE = "Differences between v1 and v2"

    # region wiki_description
    WIKI_DESCRIPTION = """
    Detect all differences between the original contract and the updated one.
    """
    # endregion wiki_description

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
    Not an exploit, just informational.
    """
    # endregion wiki_exploit_scenario

    # region wiki_recommendation
    WIKI_RECOMMENDATION = """
    Use with targeted differential fuzzing to detect any unexpected discrepancies.
    """
    # endregion wiki_recommendation

    REQUIRE_CONTRACT = True
    REQUIRE_PROXY = False
    REQUIRE_CONTRACT_V2 = True

    def _contract1(self):
        return self.contract

    def _contract2(self):
        return self.contract_v2

    def _check(self):
        contract1 = self._contract1()
        contract2 = self._contract2()
        order_vars1 = [variable for variable in contract1.state_variables if not variable.is_constant]
        order_vars2 = [variable for variable in contract2.state_variables if not variable.is_constant]

        results = []

        if len(order_vars2) <= len(order_vars1):
            # Handle by MissingVariable
            return results

        for idx, var in enumerate(order_vars2):
            # Handle incorrect variable order in DifferentVariableContractNewContract
            slot = contract2.state_variable_slots[var]
            # print(f"Variable {idx}, {var} at slot {slot}")
            if len(order_vars1) <= idx:
                info = [
                    "New variable in ",
                    contract2,
                    " at slot ",
                    str(slot),
                    "\n",
                ]
                info += ["\t ", var, "\n"]
                json = self.generate_result(info)
                results.append(json)
                continue



        return results
