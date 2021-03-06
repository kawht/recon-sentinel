#     Copyright 2016, Kay Hayen, mailto:kay.hayen@gmail.com
#
#     Part of "Nuitka", an optimizing Python compiler that is compatible and
#     integrates with CPython, but also works on its own.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
#
""" This module is providing helper functions for complex call re-formulations.

One for each type of call. """

from nuitka.nodes.AssignNodes import (
    ExpressionTargetTempVariableRef,
    ExpressionTargetVariableRef,
    StatementAssignmentVariable,
    StatementReleaseVariable
)
from nuitka.nodes.AttributeNodes import ExpressionAttributeLookup
from nuitka.nodes.BuiltinDictNodes import ExpressionBuiltinDict
from nuitka.nodes.BuiltinIteratorNodes import (
    ExpressionBuiltinIter1,
    ExpressionBuiltinNext1
)
from nuitka.nodes.BuiltinRefNodes import (
    ExpressionBuiltinAnonymousRef,
    ExpressionBuiltinRef
)
from nuitka.nodes.BuiltinTypeNodes import ExpressionBuiltinTuple
from nuitka.nodes.CallNodes import (
    ExpressionCall,
    ExpressionCallEmpty,
    ExpressionCallKeywordsOnly,
    ExpressionCallNoKeywords
)
from nuitka.nodes.ComparisonNodes import (
    ExpressionComparisonIn,
    ExpressionComparisonIsNOT
)
from nuitka.nodes.ConditionalNodes import StatementConditional
from nuitka.nodes.ConstantRefNodes import ExpressionConstantRef
from nuitka.nodes.ContainerMakingNodes import ExpressionMakeTuple
from nuitka.nodes.DictionaryNodes import StatementDictOperationSet
from nuitka.nodes.ExceptionNodes import (
    ExpressionBuiltinMakeException,
    StatementRaiseException
)
from nuitka.nodes.FunctionNodes import (
    ExpressionFunctionBody,
    ExpressionFunctionCall,
    ExpressionFunctionCreation,
    ExpressionFunctionRef
)
from nuitka.nodes.LoopNodes import StatementLoop, StatementLoopBreak
from nuitka.nodes.OperatorNodes import ExpressionOperationBinary
from nuitka.nodes.ParameterSpecs import ParameterSpec
from nuitka.nodes.ReturnNodes import StatementReturn
from nuitka.nodes.SubscriptNodes import (
    ExpressionSubscriptLookup,
    StatementAssignmentSubscript
)
from nuitka.nodes.TypeNodes import (
    ExpressionBuiltinIsinstance,
    ExpressionBuiltinType1
)
from nuitka.nodes.VariableRefNodes import (
    ExpressionTempVariableRef,
    ExpressionVariableRef
)
from nuitka.PythonVersions import (
    getComplexCallSequenceErrorTemplate,
    python_version
)

from .Helpers import (
    makeConditionalStatement,
    makeStatementsSequenceFromStatement,
    makeStatementsSequenceFromStatements
)
from .InternalModule import (
    getInternalModule,
    internal_source_ref,
    once_decorator
)
from .ReformulationTryExceptStatements import makeTryExceptSingleHandlerNode
from .ReformulationTryFinallyStatements import makeTryFinallyStatement


def orderArgs(*args):
    if python_version >= 350:
        def weight(arg):
            result = args.index(arg)

            if arg == "kw":
                result += 1.5
            elif arg == "star_arg_list":
                result -= 1.5

            return result

        return tuple(
            sorted(args, key = weight)
        )

    return args

@once_decorator
def getCallableNameDescBody():
    helper_name = "get_callable_name_desc"

    # Equivalent of:
    #
    # Note: The "called_type" is a temporary variable.
    #
    # called_type = type( BuiltinFunctionType )
    #
    # if ininstance( called, (FunctionType, MethodType, BuiltinFunctionType) ):
    #     return called.__name__
    # elif python_version < 3 and isinstance( called, ClassType ):
    #     return called_type.__name__ + " constructor"
    # elif python_version < 3 and isinstance( called, InstanceType ):
    #     return called_type.__name__ + " instance"
    # else:
    #     return called_type.__name__ + " object"

    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called",
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    def makeNameAttributeLookup(node, attribute_name = "__name__"):
        return ExpressionAttributeLookup(
            source         = node,
            attribute_name = attribute_name,
            source_ref     = internal_source_ref
        )

    functions_case = makeStatementsSequenceFromStatement(
        statement = (
            StatementReturn(
                expression = ExpressionOperationBinary(
                    operator   = "Add",
                    right      = ExpressionConstantRef(
                        constant      = "()",
                        source_ref    = internal_source_ref,
                        user_provided = True
                    ),
                    left       = makeNameAttributeLookup(
                        ExpressionVariableRef(
                            variable_name = "called",
                            variable      = called_variable,
                            source_ref    = internal_source_ref
                        )
                    ),
                    source_ref = internal_source_ref

                ),
                source_ref = internal_source_ref
            )
        )
    )

    no_branch = StatementReturn(
        expression = ExpressionOperationBinary(
            operator   = "Add",
            right      = ExpressionConstantRef(
                constant      = " object",
                source_ref    = internal_source_ref,
                user_provided = True
            ),
            left       = makeNameAttributeLookup(
                ExpressionBuiltinType1(
                    value      = ExpressionVariableRef(
                        variable_name = "called",
                        variable      = called_variable,
                        source_ref    = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                )
            ),
            source_ref = internal_source_ref
        ),
        source_ref = internal_source_ref
    )

    if python_version < 300:
        instance_case = StatementReturn(
            expression = ExpressionOperationBinary(
                operator   = "Add",
                right      = ExpressionConstantRef(
                    constant      = " instance",
                    source_ref    = internal_source_ref,
                    user_provided = True
                ),
                left       = makeNameAttributeLookup(
                    makeNameAttributeLookup(
                        ExpressionVariableRef(
                            variable_name = "called",
                            variable      = called_variable,
                            source_ref    = internal_source_ref
                        ),
                        attribute_name = "__class__",
                    )
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )

        no_branch = makeConditionalStatement(
            condition  = ExpressionBuiltinIsinstance(
                instance   = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                classes    = ExpressionBuiltinAnonymousRef(
                    builtin_name = "instance",
                    source_ref   = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            yes_branch = instance_case,
            no_branch  = no_branch,
            source_ref = internal_source_ref
        )

        class_case = StatementReturn(
            expression = ExpressionOperationBinary(
                operator   = "Add",
                right      = ExpressionConstantRef(
                    constant      = " constructor",
                    source_ref    = internal_source_ref,
                    user_provided = True
                ),
                left       = makeNameAttributeLookup(
                    ExpressionVariableRef(
                        variable_name = "called",
                        variable      = called_variable,
                        source_ref    = internal_source_ref
                    ),
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )

        no_branch = makeConditionalStatement(
            condition  = ExpressionBuiltinIsinstance(
                instance   = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                classes    = ExpressionBuiltinAnonymousRef(
                    builtin_name = "classobj",
                    source_ref   = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            yes_branch = class_case,
            no_branch  = no_branch,
            source_ref = internal_source_ref
        )

    if python_version < 300:
        normal_cases = (
            "function", "builtin_function_or_method", "instancemethod"
        )
    else:
        normal_cases = (
            "function", "builtin_function_or_method"
        )

    result.setBody(
        makeStatementsSequenceFromStatement(
            statement = makeConditionalStatement(
                condition  = ExpressionBuiltinIsinstance(
                    instance   = ExpressionVariableRef(
                        variable_name = "called",
                        variable      = called_variable,
                        source_ref    = internal_source_ref
                    ),
                    classes    = ExpressionMakeTuple(
                        elements   = tuple(
                            ExpressionBuiltinAnonymousRef(
                                builtin_name = builtin_name,
                                source_ref   = internal_source_ref
                            )
                            for builtin_name in
                            normal_cases
                        ),
                        source_ref = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                yes_branch = functions_case,
                no_branch  = no_branch,
                source_ref = internal_source_ref
            )
        )
    )

    return result


def makeStarListArgumentErrorRaise(called_variable_ref, star_list_variable_ref):
    return StatementRaiseException(
        exception_type  = ExpressionBuiltinMakeException(
            exception_name = "TypeError",
            args           = (
                ExpressionOperationBinary(
                    operator   = "Mod",
                    left       =  ExpressionConstantRef(
                        constant      = getComplexCallSequenceErrorTemplate(),
                        source_ref    = internal_source_ref,
                        user_provided = True
                    ),
                    right      = ExpressionMakeTuple(
                        elements   = (
                            ExpressionFunctionCall(
                                function   = ExpressionFunctionCreation(
                                    function_ref = ExpressionFunctionRef(
                                        function_body = getCallableNameDescBody(),
                                        source_ref    = internal_source_ref
                                    ),
                                    code_object  = None,
                                    defaults     = (),
                                    kw_defaults  = None,
                                    annotations  = None,
                                    source_ref   = internal_source_ref
                                ),
                                values     = (
                                    called_variable_ref,
                                ),
                                source_ref = internal_source_ref
                            ),
                            ExpressionAttributeLookup(
                                source         = ExpressionBuiltinType1(
                                    value      = star_list_variable_ref.makeClone(),
                                    source_ref = internal_source_ref
                                ),
                                attribute_name = "__name__",
                                source_ref     = internal_source_ref
                            )
                        ),
                        source_ref = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
            ),
            source_ref     = internal_source_ref
        ),
        exception_value = None,
        exception_trace = None,
        exception_cause = None,
        source_ref      = internal_source_ref
    )


def _makeStarListArgumentToTupleStatement(called_variable_ref,
                                          star_list_target_variable_ref,
                                          star_list_variable_ref):
    return makeConditionalStatement(
        condition  = ExpressionComparisonIsNOT(
            left       = ExpressionBuiltinType1(
                value      = star_list_variable_ref.makeClone(),
                source_ref = internal_source_ref
            ),
            right      = ExpressionBuiltinRef(
                builtin_name = "tuple",
                source_ref   = internal_source_ref
            ),
            source_ref = internal_source_ref
        ),
        yes_branch = makeTryExceptSingleHandlerNode(
            tried          =  StatementAssignmentVariable(
                variable_ref = star_list_target_variable_ref.makeClone(),
                source       = ExpressionBuiltinTuple(
                    value      = star_list_variable_ref.makeClone(),
                    source_ref = internal_source_ref
                ),
                source_ref   = internal_source_ref
            ),
            exception_name = "TypeError",
            handler_body   = makeStarListArgumentErrorRaise(
                called_variable_ref    = called_variable_ref,
                star_list_variable_ref = star_list_variable_ref
            ),
            source_ref     = internal_source_ref
        ),
        no_branch  = None,
        source_ref = internal_source_ref
    )


def _makeRaiseExceptionMustBeMapping(called_variable_ref,
                                     star_dict_variable_ref):
    return StatementRaiseException(
        exception_type  = ExpressionBuiltinMakeException(
            exception_name = "TypeError",
            args           = (
                ExpressionOperationBinary(
                    operator   = "Mod",
                    left       =  ExpressionConstantRef(
                        constant      = """\
%s argument after ** must be a mapping, not %s""",
                        source_ref    = internal_source_ref,
                        user_provided = True
                    ),
                    right      = ExpressionMakeTuple(
                        elements   = (
                            ExpressionFunctionCall(
                                function   = ExpressionFunctionCreation(
                                    function_ref = ExpressionFunctionRef(
                                        function_body = getCallableNameDescBody(),
                                        source_ref    = internal_source_ref
                                    ),
                                    code_object  = None,
                                    defaults     = (),
                                    kw_defaults  = None,
                                    annotations  = None,
                                    source_ref   = internal_source_ref
                                ),
                                values     = (
                                    called_variable_ref.makeClone(),
                                ),
                                source_ref = internal_source_ref
                            ),
                            ExpressionAttributeLookup(
                                source         = ExpressionBuiltinType1(
                                    value      = ExpressionVariableRef(
                                        variable_name = star_dict_variable_ref.getVariableName(),
                                        variable      = star_dict_variable_ref.getVariable(),
                                        source_ref    = internal_source_ref
                                    ),
                                    source_ref = internal_source_ref
                                ),
                                attribute_name = "__name__",
                                source_ref     = internal_source_ref
                            )
                        ),
                        source_ref = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
            ),
            source_ref     = internal_source_ref
        ),
        exception_value = None,
        exception_trace = None,
        exception_cause = None,
        source_ref      = internal_source_ref
    )


def _makeIteratingLoopStatement(tmp_iter_variable, tmp_item_variable, statements):
    loop_body = makeStatementsSequenceFromStatements(
        makeTryExceptSingleHandlerNode(
            tried          = StatementAssignmentVariable(
                variable_ref = ExpressionTargetTempVariableRef(
                    variable   = tmp_item_variable,
                    source_ref = internal_source_ref
                ),
                source       = ExpressionBuiltinNext1(
                    value      = ExpressionTempVariableRef(
                        variable   = tmp_iter_variable,
                        source_ref = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                source_ref   = internal_source_ref
            ),
            exception_name = "StopIteration",
            handler_body   = StatementLoopBreak(
                source_ref = internal_source_ref
            ),
            source_ref     = internal_source_ref
        ),
        *statements
    )

    return StatementLoop(
        body       = loop_body,
        source_ref = internal_source_ref
    )


def _makeStarDictArgumentToDictStatement(result, called_variable_ref,
                                         star_dict_target_variable_ref,
                                         star_dict_variable_ref):
    temp_scope = result.allocateTempScope("mapping")

    tmp_dict_variable = result.allocateTempVariable(temp_scope, "dict")
    tmp_iter_variable = result.allocateTempVariable(temp_scope, "iter")
    tmp_keys_variable = result.allocateTempVariable(temp_scope, "keys")
    tmp_key_variable = result.allocateTempVariable(temp_scope, "key")

    loop_body = (
        StatementAssignmentSubscript(
            expression = ExpressionTempVariableRef(
                variable   = tmp_dict_variable,
                source_ref = internal_source_ref
            ),
            subscript  = ExpressionTempVariableRef(
                variable   = tmp_key_variable,
                source_ref = internal_source_ref
            ),
            source     = ExpressionSubscriptLookup(
                subscribed = star_dict_variable_ref.makeClone(),
                subscript  = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        ),
    )

    mapping_case = makeStatementsSequenceFromStatements(
        # Initializing the temp variable outside of try/except, because code
        # generation does not yet detect that case properly. TODO: Can be
        # removed once code generation is apt enough.
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_keys_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionConstantRef(
                constant      = None,
                source_ref    = internal_source_ref,
                user_provided = True
            ),
            source_ref   = internal_source_ref
        ),
        makeTryExceptSingleHandlerNode(
            tried          = StatementAssignmentVariable(
                variable_ref = ExpressionTargetTempVariableRef(
                    variable   = tmp_keys_variable,
                    source_ref = internal_source_ref
                ),
                source       = ExpressionCallEmpty(
                    called     = ExpressionAttributeLookup(
                        source         = star_dict_variable_ref.makeClone(),
                        attribute_name = "keys",
                        source_ref     = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                source_ref   = internal_source_ref
            ),
            exception_name = "AttributeError",
            handler_body   = _makeRaiseExceptionMustBeMapping(
                called_variable_ref    = called_variable_ref,
                star_dict_variable_ref = star_dict_target_variable_ref
            ),
            source_ref     = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_iter_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionBuiltinIter1(
                value      = ExpressionTempVariableRef(
                    variable   = tmp_keys_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_dict_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionConstantRef(
                constant      = {},
                source_ref    = internal_source_ref,
                user_provided = True
            ),
            source_ref   = internal_source_ref
        ),
        _makeIteratingLoopStatement(
            tmp_iter_variable = tmp_iter_variable,
            tmp_item_variable = tmp_key_variable,
            statements        = loop_body
        ),
        StatementAssignmentVariable(
            variable_ref = star_dict_target_variable_ref.makeClone(),
            source       = ExpressionTempVariableRef(
                variable   = tmp_dict_variable,
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
    )

    tried = StatementConditional(
        condition  = ExpressionComparisonIsNOT(
            left       = ExpressionBuiltinType1(
                value      = star_dict_variable_ref.makeClone(),
                source_ref = internal_source_ref
            ),
            right      = ExpressionBuiltinRef(
                builtin_name = "dict",
                source_ref   = internal_source_ref
            ),
            source_ref = internal_source_ref
        ),
        yes_branch = mapping_case,
        no_branch  = None,
        source_ref = internal_source_ref
    )

    final = (
        StatementReleaseVariable(
            variable   = tmp_dict_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_iter_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_keys_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_key_variable,
            source_ref = internal_source_ref
        )
    )

    return makeTryFinallyStatement(
        provider   = result,
        tried      = tried,
        final      = final,
        source_ref = internal_source_ref
    )


def _makeRaiseDuplicationItem(called_variable, tmp_key_variable):
    return StatementRaiseException(
        exception_type  = ExpressionBuiltinMakeException(
            exception_name = "TypeError",
            args           = (
                ExpressionOperationBinary(
                    operator   = "Mod",
                    left       =  ExpressionConstantRef(
                        constant      = """\
%s got multiple values for keyword argument '%s'""",
                        source_ref    = internal_source_ref,
                        user_provided = True
                    ),
                    right      = ExpressionMakeTuple(
                        elements   = (
                            ExpressionFunctionCall(
                                function   = ExpressionFunctionCreation(
                                    function_ref = ExpressionFunctionRef(
                                        function_body = getCallableNameDescBody(
                                        ),
                                        source_ref    = internal_source_ref
                                    ),
                                    code_object  = None,
                                    defaults     = (),
                                    kw_defaults  = None,
                                    annotations  = None,
                                    source_ref   = internal_source_ref
                                ),
                                values     = (
                                    ExpressionVariableRef(
                                        variable      = called_variable,
                                        variable_name = called_variable.getName(),
                                        source_ref    = internal_source_ref
                                    ),
                                ),
                                source_ref = internal_source_ref
                            ),
                            ExpressionTempVariableRef(
                                variable   = tmp_key_variable,
                                source_ref = internal_source_ref
                            )
                        ),
                        source_ref = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
            ),
            source_ref     = internal_source_ref
        ),
        exception_value = None,
        exception_trace = None,
        exception_cause = None,
        source_ref      = internal_source_ref
    )


def _makeStarDictArgumentMergeToKwStatement(result, called_variable_ref,
                                            kw_target_variable_ref,
                                            kw_variable_ref,
                                            star_dict_variable_ref):
    # This is plain terribly complex, pylint: disable=R0914
    temp_scope = result.allocateTempScope("dict")

    tmp_dict_variable = result.allocateTempVariable(temp_scope, "dict")
    tmp_iter_variable = result.allocateTempVariable(temp_scope, "iter")
    tmp_keys_variable = result.allocateTempVariable(temp_scope, "keys")
    tmp_key_variable = result.allocateTempVariable(temp_scope, "key_xxx")

    final = [
        StatementReleaseVariable(
            variable   = tmp_dict_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_iter_variable,
            source_ref = internal_source_ref,
        ),
        StatementReleaseVariable(
            variable   = tmp_keys_variable,
            source_ref = internal_source_ref,
        ),
        StatementReleaseVariable(
            variable   = tmp_key_variable,
            source_ref = internal_source_ref,
        )
    ]

    mapping_loop_body = (
        StatementConditional(
            condition  = ExpressionComparisonIn(
                left       = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                right      = kw_variable_ref.makeClone(),
                source_ref = internal_source_ref
            ),
            yes_branch = makeStatementsSequenceFromStatement(
                statement = _makeRaiseDuplicationItem(
                    called_variable  = called_variable_ref.getVariable(),
                    tmp_key_variable = tmp_key_variable
                )
            ),
            no_branch  = None,
            source_ref = internal_source_ref
        ),
        StatementAssignmentSubscript(
            expression = kw_variable_ref.makeClone(),
            subscript  = ExpressionTempVariableRef(
                variable   = tmp_key_variable,
                source_ref = internal_source_ref
            ),
            source     = ExpressionSubscriptLookup(
                subscribed = star_dict_variable_ref.makeClone(),
                subscript  = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    mapping_case = makeStatementsSequenceFromStatements(
        # Initializing the temp variable outside of try/except, because code
        # generation does not yet detect that case properly. TODO: Can be
        # removed once code generation is apt enough.
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_keys_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionConstantRef(
                constant      = None,
                source_ref    = internal_source_ref,
                user_provided = True
            ),
            source_ref   = internal_source_ref
        ),
        makeTryExceptSingleHandlerNode(
            tried          = StatementAssignmentVariable(
                variable_ref = ExpressionTargetTempVariableRef(
                    variable   = tmp_keys_variable,
                    source_ref = internal_source_ref
                ),
                source       = ExpressionCallEmpty(
                    called     = ExpressionAttributeLookup(
                        source         = star_dict_variable_ref.makeClone(),
                        attribute_name = "keys",
                        source_ref     = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                source_ref   = internal_source_ref
            ),
            exception_name = "AttributeError",
            handler_body   = _makeRaiseExceptionMustBeMapping(
                called_variable_ref    = called_variable_ref,
                star_dict_variable_ref = star_dict_variable_ref
            ),
            source_ref     = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_iter_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionBuiltinIter1(
                value      = ExpressionTempVariableRef(
                    variable   = tmp_keys_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_dict_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionConstantRef(
                constant      = {},
                source_ref    = internal_source_ref,
                user_provided = True
            ),
            source_ref   = internal_source_ref
        ),
        _makeIteratingLoopStatement(
            tmp_iter_variable = tmp_iter_variable,
            tmp_item_variable = tmp_key_variable,
            statements        = mapping_loop_body
        )
    )

    temp_scope = result.allocateTempScope("dict")

    tmp_iter_variable = result.allocateTempVariable(temp_scope, "iter")
    tmp_item_variable = result.allocateTempVariable(temp_scope, "item")
    tmp_key_variable = result.allocateTempVariable(temp_scope, "key")

    final += [
        StatementReleaseVariable(
            variable   = tmp_iter_variable,
            source_ref = internal_source_ref,
        ),
        StatementReleaseVariable(
            variable   = tmp_item_variable,
            source_ref = internal_source_ref,
        ),
        StatementReleaseVariable(
            variable   = tmp_key_variable,
            source_ref = internal_source_ref,
        )
    ]

    dict_loop_body = (
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_key_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionSubscriptLookup(
                subscribed = ExpressionTempVariableRef(
                    variable   = tmp_item_variable,
                    source_ref = internal_source_ref
                ),
                subscript  = ExpressionConstantRef(
                    constant      = 0,
                    source_ref    = internal_source_ref,
                    user_provided = True
                ),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        StatementConditional(
            condition  = ExpressionComparisonIn(
                left       = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                right      = kw_variable_ref.makeClone(),
                source_ref = internal_source_ref
            ),
            yes_branch = makeStatementsSequenceFromStatement(
                statement = _makeRaiseDuplicationItem(
                    called_variable  = called_variable_ref.getVariable(),
                    tmp_key_variable = tmp_key_variable
                )
            ),
            no_branch  = None,
            source_ref = internal_source_ref
        ),
        StatementAssignmentSubscript(
            expression = kw_variable_ref.makeClone(),
            subscript  = ExpressionTempVariableRef(
                variable   = tmp_key_variable,
                source_ref = internal_source_ref
            ),
            source     = ExpressionSubscriptLookup(
                subscribed = ExpressionTempVariableRef(
                    variable   = tmp_item_variable,
                    source_ref = internal_source_ref
                ),
                subscript  = ExpressionConstantRef(
                    constant      = 1,
                    source_ref    = internal_source_ref,
                    user_provided = True
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    dict_case = makeStatementsSequenceFromStatements(
        StatementAssignmentVariable(
            variable_ref = kw_target_variable_ref.makeClone(),
            source       = ExpressionBuiltinDict(
                pos_arg    = kw_variable_ref.makeClone(),
                pairs      = (),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_iter_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionBuiltinIter1(
                value      = ExpressionCallEmpty(
                    called     = ExpressionAttributeLookup(
                        source         = star_dict_variable_ref.makeClone(),
                        attribute_name = "iteritems"
                                           if python_version < 300 else
                                         "items",
                        source_ref     = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        _makeIteratingLoopStatement(
            tmp_iter_variable = tmp_iter_variable,
            tmp_item_variable = tmp_item_variable,
            statements        = dict_loop_body,
        ),
    )

    dict_case = makeStatementsSequenceFromStatement(
        statement = StatementConditional(
            condition  = star_dict_variable_ref.makeClone(),
            yes_branch = dict_case,
            no_branch  = None,
            source_ref = internal_source_ref
        )
    )

    tried = StatementConditional(
        condition  = ExpressionComparisonIsNOT(
            left       = ExpressionBuiltinType1(
                value      = star_dict_variable_ref.makeClone(),
                source_ref = internal_source_ref
            ),
            right      = ExpressionBuiltinRef(
                builtin_name = "dict",
                source_ref   = internal_source_ref
            ),
            source_ref = internal_source_ref
        ),
        yes_branch = mapping_case,
        no_branch  = dict_case,
        source_ref = internal_source_ref
    )

    return makeTryFinallyStatement(
        provider   = result,
        tried      = tried,
        final      = final,
        source_ref = internal_source_ref
    )


@once_decorator
def getFunctionCallHelperStarList():
    helper_name = "complex_call_helper_star_list"
    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_list, tuple ):
    #     try:
    #         star_arg_list = tuple( star_arg_list )
    #     except TypeError:
    #         raise TypeError, "%s argument after * must be a sequence, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_list ).__name__
    #         )
    #
    # return called( *star_arg_list )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "star_arg_list"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )
    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    statements = (
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCallNoKeywords(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "star_arg_list",
                    variable      = star_arg_list_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperKeywordsStarList():
    helper_name = "complex_call_helper_keywords_star_list"

    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_list, tuple ):
    #     try:
    #         star_arg_list = tuple( star_arg_list )
    #     except TypeError:
    #         raise TypeError, "%s argument after * must be a sequence, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_list ).__name__
    #         )
    #
    # return called( *star_arg_list )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = orderArgs(
                "called", "kw", "star_arg_list"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    statements = (
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "star_arg_list",
                    variable      = star_arg_list_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosStarList():
    helper_name = "complex_call_helper_pos_star_list"

    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_list, tuple ):
    #     try:
    #         star_arg_list = tuple( star_arg_list )
    #     except TypeError:
    #         raise TypeError, "%s argument after * must be a sequence, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_list ).__name__
    #         )
    #
    # return called( *star_arg_list )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "args", "star_arg_list"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    statements = (
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCallNoKeywords(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionOperationBinary(
                    operator   = "Add",
                    left       = ExpressionVariableRef(
                        variable_name = "args",
                        variable      = args_variable,
                        source_ref    = internal_source_ref
                    ),
                    right      = ExpressionVariableRef(
                        variable_name = "star_arg_list",
                        variable      = star_arg_list_variable,
                        source_ref    = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosKeywordsStarList():
    helper_name = "complex_call_helper_pos_keywords_star_list"
    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_list, tuple ):
    #     try:
    #         star_arg_list = tuple( star_arg_list )
    #     except TypeError:
    #         raise TypeError, "%s argument after * must be a sequence, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_list ).__name__
    #         )
    #
    # return called( *star_arg_list )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = orderArgs(
                "called", "args", "kw", "star_arg_list"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    statements = (
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref =  ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionOperationBinary(
                    operator   = "Add",
                    left       = ExpressionVariableRef(
                        variable_name = "args",
                        variable      = args_variable,
                        source_ref    = internal_source_ref
                    ),
                    right      = ExpressionVariableRef(
                        variable_name = "star_arg_list",
                        variable      = star_arg_list_variable,
                        source_ref    = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperStarDict():
    helper_name = "complex_call_helper_star_dict"
    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_dict, dict ):
    #     try:
    #         tmp_keys =  star_arg_dict.keys()
    #     except AttributeError:
    #         raise TypeError, ""%s argument after ** must be a mapping, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_dict ).__name__
    #         )
    #
    #     tmp_iter = iter( keys )
    #     tmp_dict = {}
    #
    #     while 1:
    #         try:
    #             tmp_key = tmp_iter.next()
    #         except StopIteration:
    #             break
    #
    #         tmp_dict[ tmp_key ] = star_dict_arg[ tmp_key )
    #
    #     star_arg_dict = new
    #
    # return called( **star_arg_dict )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentToDictStatement(
            result                        = result,
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCallKeywordsOnly(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "star_arg_dict",
                    variable      = star_arg_dict_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosStarDict():
    helper_name = "complex_call_helper_pos_star_dict"

    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call.
    #
    # if not isinstance( star_arg_dict, dict ):
    #     try:
    #         tmp_keys =  star_arg_dict.keys()
    #     except AttributeError:
    #         raise TypeError, ""%s argument after ** must be a mapping, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_dict ).__name__
    #         )
    #
    #     tmp_iter = iter( keys )
    #     tmp_dict = {}
    #
    #     while 1:
    #         try:
    #             tmp_key = tmp_iter.next()
    #         except StopIteration:
    #             break
    #
    #         tmp_dict[ tmp_key ] = star_dict_arg[ tmp_key )
    #
    #     star_arg_dict = new
    #
    # return called( args, **star_arg_dict )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "args", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentToDictStatement(
            result                        = result,
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "args",
                    variable      = args_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "star_arg_dict",
                    variable      = star_arg_dict_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperKeywordsStarDict():
    helper_name = "complex_call_helper_keywords_star_dict"
    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call. One goal is to avoid copying "kw" unless really
    # necessary, and to take the slow route only for non-dictionaries.
    #
    # if not isinstance( star_arg_dict, dict ):
    #     try:
    #         tmp_keys =  star_arg_dict.keys()
    #     except AttributeError:
    #         raise TypeError, ""%s argument after ** must be a mapping, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_dict ).__name__
    #         )
    #
    #     if keys:
    #         kw = dict( kw )
    #
    #         tmp_iter = iter( keys )
    #         tmp_dict = {}
    #
    #         while 1:
    #             try:
    #                 tmp_key = tmp_iter.next()
    #             except StopIteration:
    #                  break
    #
    #             if tmp_key in kw:
    #                 raise TypeError, "%s got multiple values for keyword argument '%s'" % (
    #                     get_callable_name_desc( function ),
    #                     tmp_key
    #                 )
    #
    #             kw[ tmp_key ] = star_dict_arg[ tmp_key )
    #
    # elif star_arg_dict:
    #    tmp_iter = star_arg_dict.iteritems()
    #
    #    kw = dict( kw )
    #    while 1:
    #        try:
    #            tmp_key, tmp_value = tmp_iter.next()
    #        except StopIteration:
    #            break
    #
    #        if tmp_key in kw:
    #            raise TypeError, "%s got multiple values for keyword argument '%s'" % (
    #                 get_callable_name_desc( function ),
    #                 tmp_key
    #            )
    #
    #        kw[ tmp_key ] = tmp_value
    #
    # return called( **kw  )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "kw", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentMergeToKwStatement(
            result                 = result,
            called_variable_ref    = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            kw_variable_ref        = ExpressionVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            kw_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCallKeywordsOnly(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosKeywordsStarDict():
    helper_name = "complex_call_helper_pos_keywords_star_dict"
    # Equivalent of:
    #
    # Note: Call in here is not the same, as it can go without checks directly
    # to PyObject_Call. One goal is to avoid copying "kw" unless really
    # necessary, and to take the slow route only for non-dictionaries.
    #
    # if not isinstance( star_arg_dict, dict ):
    #     try:
    #         tmp_keys =  star_arg_dict.keys()
    #     except AttributeError:
    #         raise TypeError, ""%s argument after ** must be a mapping, not %s" % (
    #             get_callable_name_desc( function ),
    #             type( star_arg_dict ).__name__
    #         )
    #
    #     if keys:
    #         kw = dict( kw )
    #
    #         tmp_iter = iter( keys )
    #         tmp_dict = {}
    #
    #         while 1:
    #             try:
    #                 tmp_key = tmp_iter.next()
    #             except StopIteration:
    #                  break
    #
    #             if tmp_key in kw:
    #                 raise TypeError, "%s got multiple values for keyword argument '%s'" % (
    #                     get_callable_name_desc( function ),
    #                     tmp_key
    #                 )
    #
    #             kw[ tmp_key ] = star_dict_arg[ tmp_key )
    #
    # elif star_arg_dict:
    #    tmp_iter = star_arg_dict.iteritems()
    #
    #    kw = dict( kw )
    #    while 1:
    #        try:
    #            tmp_key, tmp_value = tmp_iter.next()
    #        except StopIteration:
    #            break
    #
    #        if tmp_key in kw:
    #            raise TypeError, "%s got multiple values for keyword argument '%s'" % (
    #                 get_callable_name_desc( function ),
    #                 tmp_key
    #            )
    #
    #        kw[ tmp_key ] = tmp_value
    #
    # return called( **kw  )

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "args", "kw", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentMergeToKwStatement(
            result                 = result,
            called_variable_ref    = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            kw_variable_ref        = ExpressionVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            kw_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "args",
                    variable      = args_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperStarListStarDict():
    helper_name = "complex_call_helper_star_list_star_dict"

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "star_arg_list", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentToDictStatement(
            result                        = result,
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "star_arg_list",
                    variable      = star_arg_list_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "star_arg_dict",
                    variable      = star_arg_dict_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosStarListStarDict():
    helper_name = "complex_call_helper_pos_star_list_star_dict"

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called", "args", "star_arg_list", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentToDictStatement(
            result                        = result,
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionOperationBinary(
                    operator   = "Add",
                    left       = ExpressionVariableRef(
                        variable_name = "args",
                        variable      = args_variable,
                        source_ref    = internal_source_ref
                    ),
                    right      = ExpressionVariableRef(
                        variable_name = "star_arg_list",
                        variable      = star_arg_list_variable,
                        source_ref    = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "star_arg_dict",
                    variable      = star_arg_dict_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperKeywordsStarListStarDict():
    helper_name = "complex_call_helper_keywords_star_list_star_dict"

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = orderArgs(
                "called", "kw", "star_arg_list", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentMergeToKwStatement(
            result                 = result,
            called_variable_ref    = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            kw_variable_ref        = ExpressionVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            kw_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionVariableRef(
                    variable_name = "star_arg_list",
                    variable      = star_arg_list_variable,
                    source_ref    = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result

@once_decorator
def getFunctionCallHelperPosKeywordsStarListStarDict():
    helper_name = "complex_call_helper_pos_keywords_star_list_star_dict"

    # Only need to check if the star argument value is a sequence and then
    # convert to tuple.
    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = orderArgs(
                "called", "args", "kw", "star_arg_list", "star_arg_dict"
            ),
            list_star_arg = None,
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )

    kw_variable = result.getVariableForAssignment(
        variable_name = "kw"
    )

    star_arg_list_variable = result.getVariableForAssignment(
        variable_name = "star_arg_list"
    )

    star_arg_dict_variable = result.getVariableForAssignment(
        variable_name = "star_arg_dict"
    )

    statements = (
        _makeStarDictArgumentMergeToKwStatement(
            result                 = result,
            called_variable_ref    = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            kw_variable_ref        = ExpressionVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            kw_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "kw",
                variable      = kw_variable,
                source_ref    = internal_source_ref
            ),
            star_dict_variable_ref = ExpressionVariableRef(
                variable_name = "star_arg_dict",
                variable      = star_arg_dict_variable,
                source_ref    = internal_source_ref
            )
        ),
        _makeStarListArgumentToTupleStatement(
            called_variable_ref           = ExpressionVariableRef(
                variable_name = "called",
                variable      = called_variable,
                source_ref    = internal_source_ref
            ),
            star_list_variable_ref        = ExpressionVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            ),
            star_list_target_variable_ref = ExpressionTargetVariableRef(
                variable_name = "star_arg_list",
                variable      = star_arg_list_variable,
                source_ref    = internal_source_ref
            )
        ),
        StatementReturn(
            expression = ExpressionCall(
                called     = ExpressionVariableRef(
                    variable_name = "called",
                    variable      = called_variable,
                    source_ref    = internal_source_ref
                ),
                args       = ExpressionOperationBinary(
                    operator   = "Add",
                    left       = ExpressionVariableRef(
                        variable_name = "args",
                        variable      = args_variable,
                        source_ref    = internal_source_ref
                    ),
                    right      = ExpressionVariableRef(
                        variable_name = "star_arg_list",
                        variable      = star_arg_list_variable,
                        source_ref    = internal_source_ref
                    ),
                    source_ref = internal_source_ref
                ),
                kw         = ExpressionVariableRef(
                    variable_name = "kw",
                    variable      = kw_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    final = (
        StatementReleaseVariable(
            variable   = called_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = args_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = kw_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_list_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = star_arg_dict_variable,
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = statements,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result


@once_decorator
def getFunctionCallHelperDictionaryUnpacking():
    helper_name = "complex_call_helper_dict_unpacking_checks"

    result = ExpressionFunctionBody(
        provider   = getInternalModule(),
        name       = helper_name,
        doc        = None,
        parameters = ParameterSpec(
            name          = helper_name,
            normal_args   = (
                "called",
            ),
            list_star_arg = "args",
            dict_star_arg = None,
            default_count = 0,
            kw_only_args  = ()
        ),
        flags      = set(),
        source_ref = internal_source_ref
    )

    args_variable = result.getVariableForAssignment(
        variable_name = "args"
    )
    called_variable = result.getVariableForAssignment(
        variable_name = "called"
    )

    temp_scope = None

    tmp_result_variable = result.allocateTempVariable(temp_scope, "dict")
    tmp_iter_variable = result.allocateTempVariable(temp_scope, "dicts_iter")
    tmp_item_variable = result.allocateTempVariable(temp_scope, "args_item")
    tmp_iter2_variable = result.allocateTempVariable(temp_scope, "dict_iter")
    tmp_key_variable = result.allocateTempVariable(temp_scope, "dict_key")

    update_body = (
        StatementConditional(
            condition  = ExpressionComparisonIn(
                left       = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                right      = ExpressionTempVariableRef(
                    variable   = tmp_result_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            yes_branch = makeStatementsSequenceFromStatement(
                statement = _makeRaiseDuplicationItem(
                    called_variable  = called_variable,
                    tmp_key_variable = tmp_key_variable
                )
            ),
            no_branch  = None,
            source_ref = internal_source_ref
        ),
        StatementDictOperationSet(
            dict_arg   = ExpressionTempVariableRef(
                variable   = tmp_result_variable,
                source_ref = internal_source_ref

            ),
            key        = ExpressionTempVariableRef(
                variable   = tmp_key_variable,
                source_ref = internal_source_ref
            ),
            value      = ExpressionSubscriptLookup(
                subscribed = ExpressionTempVariableRef(
                    variable   = tmp_item_variable,
                    source_ref = internal_source_ref
                ),
                subscript  = ExpressionTempVariableRef(
                    variable   = tmp_key_variable,
                    source_ref = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        ),
    )

    loop_body = (
        makeTryExceptSingleHandlerNode(
            tried          = makeStatementsSequenceFromStatements(
                StatementAssignmentVariable(
                    variable_ref = ExpressionTargetTempVariableRef(
                        variable   = tmp_iter2_variable,
                        source_ref = internal_source_ref
                    ),
                    source       = ExpressionBuiltinIter1(
                        value      = ExpressionCallEmpty(
                            called     = ExpressionAttributeLookup(
                                ExpressionTempVariableRef(
                                    variable   = tmp_item_variable,
                                    source_ref = internal_source_ref
                                ),
                                attribute_name = "keys",
                                source_ref     = internal_source_ref
                            ),
                            source_ref = internal_source_ref
                        ),
                        source_ref = internal_source_ref
                    ),
                    source_ref   = internal_source_ref
                ),
                _makeIteratingLoopStatement(
                    tmp_iter_variable = tmp_iter2_variable,
                    tmp_item_variable = tmp_key_variable,
                    statements        = update_body
                )
            ),
            exception_name = "AttributeError",
            handler_body   = StatementRaiseException(
                exception_type  = ExpressionBuiltinMakeException(
                    exception_name = "TypeError",
                    args           = (
                        ExpressionOperationBinary(
                            operator   = "Mod",
                            left       =  ExpressionConstantRef(
                                constant      = """\
'%s' object is not a mapping""",
                                source_ref    = internal_source_ref,
                                user_provided = True
                            ),
                            right      = ExpressionMakeTuple(
                                elements   = (
                                    ExpressionAttributeLookup(
                                        source         = ExpressionBuiltinType1(
                                            value      = ExpressionTempVariableRef(
                                                variable   = tmp_item_variable,
                                                source_ref = internal_source_ref
                                            ),
                                            source_ref = internal_source_ref
                                        ),
                                        attribute_name = "__name__",
                                        source_ref     = internal_source_ref
                                    ),
                                ),
                                source_ref = internal_source_ref
                            ),
                            source_ref = internal_source_ref
                        ),
                    ),
                    source_ref     = internal_source_ref
                ),
                exception_value = None,
                exception_trace = None,
                exception_cause = None,
                source_ref      = internal_source_ref
            ),
            source_ref     = internal_source_ref
        ),
    )


    final = (
        StatementReleaseVariable(
            variable   = tmp_result_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_iter_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_item_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_iter2_variable,
            source_ref = internal_source_ref
        ),
        StatementReleaseVariable(
            variable   = tmp_key_variable,
            source_ref = internal_source_ref
        ),
    )

    tried = makeStatementsSequenceFromStatements(
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_iter_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionBuiltinIter1(
                value      = ExpressionVariableRef(
                    variable_name = "args",
                    variable      = args_variable,
                    source_ref    = internal_source_ref
                ),
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        StatementAssignmentVariable(
            variable_ref = ExpressionTargetTempVariableRef(
                variable   = tmp_result_variable,
                source_ref = internal_source_ref
            ),
            source       = ExpressionConstantRef(
                constant   = {},
                source_ref = internal_source_ref
            ),
            source_ref   = internal_source_ref
        ),
        _makeIteratingLoopStatement(
            tmp_iter_variable = tmp_iter_variable,
            tmp_item_variable = tmp_item_variable,
            statements        = loop_body
        ),
        StatementReturn(
            expression = ExpressionTempVariableRef(
                variable   = tmp_result_variable,
                source_ref = internal_source_ref
            ),
            source_ref = internal_source_ref
        )
    )

    result.setBody(
        makeStatementsSequenceFromStatement(
            makeTryFinallyStatement(
                provider   = result,
                tried      = tried,
                final      = final,
                source_ref = internal_source_ref
            )
        )
    )

    return result
